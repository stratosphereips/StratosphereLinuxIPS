# Regex Generator Module

The `RegexGenerator` module continuously generates one pseudo-random regex at a
time for later Zeek-side matching.

It uses the shared `LLM` module over the Redis channels `llm_request` and
`llm_response`, validates the generated regex against a benign corpus, and
stores accepted regexes in a local SQLite database that other modules can read
through `DBManager`.

## Supported regex types

- `dns_domain`
- `uri`
- `filename`
- `tls_sni`
- `certificate_cn`

## Configuration

Example:

```yaml
regex_generator:
  enabled: false
  create_log_file: false
  generation_interval_seconds: 5
  allowed_backends: []
  llm_temperature: 1.2
  llm_max_tokens: 80
  llm_response_timeout_seconds: 90
  recent_history_size: 0
  max_regex_length: 180
  regex_validation_timeout_seconds: 2
  benign_match_strength_threshold: 75
  type_weights:
    dns_domain: 1
    uri: 1
    filename: 1
    tls_sni: 1
    certificate_cn: 1
  store_dir: output/regex_generator
  persistent_store_dir: ""
  store_rejected_regexes: false
  max_stored_rejected_regexes: 10000
  seed_benign_samples: true

whitelists:
  tranco_top_benign_limit: 1000
```

Configuration reference:

- `enabled`: enables or disables the module.
- `create_log_file`: creates `output/regex_generator.log` with detailed module
  progress messages. This file rotates on the same global
  `parameters.rotation` / `parameters.rotation_period` schedule used by the
  current Slips run.
- `generation_interval_seconds`: delay between completed generation cycles.
  Set `0` to start the next cycle immediately after the previous one finishes.
- `allowed_backends`: preferred LLM backend aliases for this module.
- `llm_temperature`: generation temperature. Kept high to encourage variation.
- `llm_max_tokens`: max tokens for the LLM reply. The module asks for one regex
  line only, so this should stay small.
- `llm_response_timeout_seconds`: soft warning threshold while waiting for the
  matching `llm_response`. The module keeps waiting after this. Set `0` to
  disable the warning.
- `recent_history_size`: compatibility knob kept at `0`. Prompt history is not
  sent to the LLM; repetition is checked locally.
- `max_regex_length`: hard reject longer regexes.
- `regex_validation_timeout_seconds`: hard wall-clock timeout for local regex
  validation and benign-corpus matching. This prevents one pathological regex
  from freezing the module. Set `0` to disable it.
- `benign_match_strength_threshold`: score from `0` to `100` used during the
  benign scan. A regex is rejected only if its strongest benign match reaches
  or exceeds this threshold. Higher values are more permissive.
- `type_weights`: weighted random choice among the five regex types.
- `store_dir`: directory containing `benign_corpus.sqlite` and
  `generated_regexes.sqlite`. Absolute paths are used as-is. Relative paths are
  resolved inside the current Slips run output directory. The default
  `output/regex_generator` therefore becomes `<run_output_dir>/regex_generator`.
- `persistent_store_dir`: stable absolute directory for the regex SQLite files.
  If set, it takes precedence over `store_dir` and lets the generator reuse
  the same DBs across many Slips restarts.
- `store_rejected_regexes`: stores rejected regexes in SQLite for audit/debug
  purposes. Default `false` so discarded candidates do not fill the disk.
- `max_stored_rejected_regexes`: retention cap for rejected rows when
  `store_rejected_regexes` is enabled. Set `0` for unlimited retention.
- `seed_benign_samples`: seed the benign DB once with a small built-in sample.
- `whitelists.tranco_top_benign_limit`: number of ordered Tranco domains kept
  in Redis under `tranco_top_domains` and reused as benign data by
  `RegexGenerator` and the offline coverage report.

## Runtime flow

Each cycle does this:

1. Discover runtime-ready LLM backends with
   `self.db.get_available_llm_backends()`.
2. Choose one backend alias from `allowed_backends`, or fall back to the LLM
   default backend.
3. Choose the next regex type using weighted random selection.
4. Build a minimal fixed prompt for that type.
5. Publish one request on `llm_request`.
6. Wait for the matching `llm_response` using `request_id`.
   If the local LLM is slow, the module keeps waiting and only logs a warning
   after `llm_response_timeout_seconds`.
7. Extract one regex line from the LLM reply.
8. Apply static safety validation.
9. Check local duplicate state with a bloom filter and exact DB lookup.
10. Stream the benign corpus for that type and compute a benign match-strength
    score for each regex/string match.
11. Reject the regex only if some benign string reaches or exceeds
    `benign_match_strength_threshold`.
12. Store accepted regexes in SQLite. Rejected regexes are only persisted if
    `store_rejected_regexes` is enabled.

V1 keeps only one LLM request in flight at a time.

If `create_log_file` is enabled, the module writes detailed cycle logs to:

```text
output/regex_generator.log
```

That file includes:

- selected regex type
- selected backend
- published `llm_request` `request_id`
- slow-wait warnings while the LLM is still working
- accepted regexes
- rejected regexes and rejection reasons

Accepted regexes are always stored in:

```text
<run_output_dir>/regex_generator/generated_regexes.sqlite
```

Rejected regexes are tracked in memory during the current run to prevent cheap
repeats, but they are not stored on disk unless `store_rejected_regexes` is
enabled.

## LLM contract

Request payload:

```json
{
  "request_id": "RegexGenerator-...",
  "requester": "RegexGenerator",
  "backend": "local_qwen",
  "messages": [...],
  "temperature": 1.2,
  "max_tokens": 80,
  "metadata": {
    "regex_type": "dns_domain",
    "prompt_version": "regex-generator-v2",
    "generation_nonce": "..."
  }
}
```

The prompt requires the model to return exactly one regex line. No JSON,
explanation, or code fences. The parser still accepts JSON-shaped replies as a
fallback for compatibility, but the active prompt is raw-regex only.

## Acceptance pipeline

Static validation rejects:

- non-ASCII regexes
- regexes longer than `max_regex_length`
- lookbehind
- backreferences
- unbounded prefix/suffix patterns like `.*...*`
- obviously broad patterns like `.*` or `.+`
- nested wildcard structures that risk catastrophic backtracking
- invalid Python/Zeek-compatible syntax

After static validation, the module first checks for exact duplicate regexes
locally with a bloom filter and exact SQLite lookup, then scans the benign
corpus for the selected type and computes a benign match-strength score for
every regex/string match. The regex is rejected only if any benign string
reaches or exceeds `benign_match_strength_threshold`.

The current benign match-strength score is an estimate from `0` to `100`. It
is computed per regex and per benign string using the strongest match span
found by Python `re.finditer()`.

For one matched span, the score is:

```text
score =
  40 * span_ratio
  + 12 * start_bonus
  + 12 * end_bonus
  + 16 * full_bonus
  + 30 * specificity_ratio
  - 18 * wildcard_penalty
```

The result is clipped to the range `0..100`. The regex keeps the highest score
it obtains against that benign string. If any benign string reaches or exceeds
`benign_match_strength_threshold`, the regex is rejected.

The terms mean:

- `span_ratio = matched_span_length / benign_string_length`
- `start_bonus = 1` if the match starts at offset `0`, else `0`
- `end_bonus = 1` if the match ends at the final character, else `0`
- `full_bonus = 1` if the match covers the entire benign string, else `0`
- `specificity_ratio = literal_chars / (literal_chars + meta_tokens)`
- `wildcard_penalty = min(1.0, wildcard_points / ((literal_chars + meta_tokens) / 2))`

Regex-specific features are measured from the regex text itself:

- `literal_chars` counts explicit alphanumeric and common structural literal
  characters such as `-`, `_`, `/`, `:`, `,`, `@`, and `=`
- escaped literals such as `\.` count as literal characters
- `meta_tokens` counts regex syntax such as `.`, `[]`, `*`, `+`, `?`, groups,
  anchors, and generic escapes
- `wildcard_points` penalize broad constructs:
  - `.*` or `.+` adds `2.5`
  - bare `.` adds `1.5`
  - `[` character classes add `1.2`
  - `*`, `+`, and `?` add `1.0`
  - generic escapes such as `\w` also add penalty

Examples:

- Regex `^google\.com$` against benign string `google.com`
  - full span match, starts at `0`, ends at the end, full match bonus applies
  - specificity is high because most of the pattern is literal
  - wildcard penalty is low
  - score is very high, so this benign match is rejected

- Regex `google` against benign string `google.com`
  - only part of the string is covered
  - it starts at `0` but does not end at the final character
  - no full-match bonus
  - score is lower and may stay below the threshold

- Regex `.*com`
  - may match a long suffix, but it is penalized heavily by the wildcard term
  - this keeps broad permissive patterns from automatically looking “strong”

## Benign corpus and bloom filters

The module creates a dedicated benign corpus DB once and can seed it with a
small built-in sample for all supported types.

On each run, it also imports domain entries from the configured Slips local
whitelist file into the benign corpus for the matching domain-like regex
types:

- `dns_domain`
- `tls_sni`
- `certificate_cn`

If the daily Tranco whitelist has already been downloaded by Slips, the module
also imports the ordered configured Tranco top benign domains from Redis into
the same domain-like benign corpus.

Redis storage note:

- The original Tranco whitelist behavior is still present: Slips stores the
  full downloaded Tranco set in Redis under `tranco_whitelisted_domains`.
- Slips now additionally stores the configured top-ranked Tranco domains in
  order under `tranco_top_domains`.
- `RegexGenerator` uses this new ordered Redis list so the top-ranked Tranco
  domains can be treated as benign test data for domain-like regexes.
- The number of domains kept in `tranco_top_domains` is configured with
  `whitelists.tranco_top_benign_limit`.

It builds one in-memory bloom filter per benign type and one additional bloom
filter for generated regex hashes. These filters speed up exact membership
checks, but they do not replace the benign corpus scan. Acceptance still
requires computing the benign match-strength score against the benign corpus
and rejecting the regex only if some benign string reaches or exceeds
`benign_match_strength_threshold`.

## Stored regexes

Accepted and rejected regexes are stored in `generated_regexes.sqlite`.

Other modules should access accepted regexes through:

```python
self.db.get_generated_regexes(regex_type="dns_domain", limit=100)
self.db.get_generated_regexes_count(regex_type="dns_domain")
```

These helpers read accepted regexes by default.

## Offline coverage report

To estimate how much the accepted regexes cover several reference
populations, run the offline report script by hand against a completed Slips
run output directory:

```bash
./venv/bin/python scripts/regex_coverage_report.py \
  --run-output-dir output/eno1_2026-03-18_10:00:30 \
  --redis-port 6379
```

By default, large populations are sampled so the script finishes in practical
time. It prints terminal progress while it runs, for example:

```text
🧪 sampled estimate ███████░░░░░░░░░░░░ 31.62% | regex 247/781 | cmp 560,840/1,770,991 | type DNS Domain | ETA ⏳ 00:00:14
```

In that progress line:

- `regex 247/781` means 247 accepted regexes have been evaluated out of 781 total accepted regexes.
- `cmp 560,840/1,770,991` means regex-versus-string match operations, not raw TI entries. The number grows because many regexes are checked against many strings across the benign corpus, malicious TI, observed traffic, and reference-union populations.

The report reuses the same `0..100` match-strength function as the live
module, but it applies it to every regex/string comparison in the selected
populations:

- if the regex does not match the string, the score is `0`
- if it matches, the score is computed with the same span/anchor/specificity/
  wildcard formula used by the generator

For each regex and each population, the report now computes:

- `match_count`: how many strings matched at all
- `avg_all ± std_all`: average and standard deviation over all tested strings,
  with non-matches counted as `0`
- `avg_match ± std_match`: average and standard deviation over only the strings
  that matched

The top-regex table ranks regexes by:

```text
strength_gap = malicious_avg_all - benign_avg_all
```

This favors regexes that score strongly and/or broadly on malicious strings
while staying weak on benign strings.

The HTML report also includes a `Strength Scatter` plot per regex type:

- X axis: benign `avg_all`
- Y axis: malicious `avg_all`
- ideal area: upper-left

That plot is useful when there are too many regexes for a table alone to be
read comfortably.

If you want the exhaustive run for research, use:

```bash
./venv/bin/python scripts/regex_coverage_report.py \
  --run-output-dir /path/to/regex_store \
  --redis-port 23456 \
  --ti-cache-port 6379 \
  --ti-cache-db 1 \
  --full-scan
```

Useful knobs:

- `--sampling-ratio`: fraction of strings to evaluate from each regex-type population in estimate mode. This is applied separately to the benign corpus values, malicious TI values, observed traffic values, and reference-union values. Default: `0.1`.
- `--max-population-size`: hard cap on the number of strings evaluated for each regex type inside each population, after `--sampling-ratio` is applied.
- `--full-scan`: disable both `--sampling-ratio` and `--max-population-size`, and scan all strings in all populations for every regex type.
- `--match-timeout-seconds`: timeout for one regex tested against one regex-type population of strings.

This generates:

- `regex_generator_coverage_report.html`
- `regex_generator_coverage_report.json`

inside the selected run output directory.

The report estimates coverage against:

- the local benign corpus DB, grouped by regex type
- the configured Tranco top benign domains from `whitelists.tranco_top_benign_limit` as extra benign data for domain-like types, when available in the Slips cache
- TI-derived malicious reference strings from Redis and TI files, grouped by regex type
- observed traffic strings from the same run, grouped by regex type and taken from Zeek logs or `flows.sqlite`
- the per-type reference union, which is `malicious TI ∪ observed traffic`

The report is offline only. It is not part of the continuous RegexGenerator
loop.
