# Regex Generator Module

The `RegexGenerator` module continuously creates one pseudo-random regex at a
time for later Zeek-side use.

It uses the shared `LLM` module over Redis, validates the generated regex
against a benign corpus, and stores accepted regexes in a dedicated local
SQLite database that later Slips modules can read through `DBManager`.

## What it does

The module:

1. Reads its configuration from `config/slips.yaml`
2. Discovers runtime-ready LLM backends using the shared LLM registry
3. Chooses the next regex type with weighted random selection
4. Sends one generation request over `llm_request`
5. Waits for the matching `llm_response`
6. Validates the regex and tests it against a benign corpus
7. Stores accepted results in local SQLite. Rejected results are only persisted
   if explicitly enabled.

Supported regex types:

- `dns_domain`
- `uri`
- `filename`
- `tls_sni`
- `certificate_cn`

## Configuration

Example section in `config/slips.yaml`:

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
- `allowed_backends`: preferred backend aliases for this module.
- `llm_temperature`: generation temperature. Kept high to keep outputs varied.
- `llm_max_tokens`: max tokens for the LLM reply. The module asks for one regex
  line only, so keep this small.
- `llm_response_timeout_seconds`: soft warning threshold while waiting for the
  matching `llm_response`. The module keeps waiting after this. Set `0` to
  disable the warning.
- `recent_history_size`: compatibility knob kept at `0`. Prompt history is not
  sent to the LLM; repetition is checked locally.
- `max_regex_length`: hard reject longer regexes.
- `regex_validation_timeout_seconds`: hard wall-clock timeout for local regex
  validation and benign-corpus matching. This prevents one pathological regex
  from freezing the module. Set `0` to disable it.
- `type_weights`: weighted random choice among the supported regex types.
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

## LLM request and response usage

The module uses the existing shared LLM channels only:

- request channel: `llm_request`
- response channel: `llm_response`

Each generation request includes:

- `request_id`
- `requester = "RegexGenerator"`
- `backend`
- `messages`
- `temperature`
- `max_tokens`
- `metadata.regex_type`
- `metadata.prompt_version`
- `metadata.generation_nonce`

The prompt requires the model to return exactly one regex line. No JSON,
explanation, or code fences. The parser still accepts JSON-shaped replies as a
fallback for compatibility, but the active prompt is raw-regex only.

V1 keeps one request in flight at a time, so response correlation is simple:
only the matching `request_id` is accepted.
If the local LLM is slow, the module keeps waiting and only logs a warning
after `llm_response_timeout_seconds`.

If `create_log_file` is enabled, the module also writes detailed progress logs
to:

```text
output/regex_generator.log
```

This file records:

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

Rejected regexes are tracked in memory during the current run to reduce cheap
repeats, but they are not stored on disk unless `store_rejected_regexes` is
enabled.

## Acceptance pipeline

After the matching `llm_response` arrives, the module:

1. Extracts one regex line from the LLM reply
3. Rejects empty or malformed results
4. Applies static safety validation
5. Checks local duplicates with a bloom filter and exact SQLite lookup
6. Streams the benign corpus for the selected type
7. Rejects on the first benign match
8. Stores accepted regexes for later use

Static validation rejects:

- non-ASCII regexes
- regexes longer than `max_regex_length`
- lookbehind
- backreferences
- unbounded `.*`-style prefix/suffix patterns
- obviously broad patterns such as `.*` and `.+`
- nested wildcard structures that risk catastrophic backtracking
- invalid syntax

## Benign corpus and bloom filters

The module creates a benign corpus DB once and can seed it with a small sample
for all five regex types.

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

- Slips still stores the full downloaded Tranco whitelist in Redis under
  `tranco_whitelisted_domains`.
- Slips now also stores a second Redis key, `tranco_top_domains`, as an
  ordered list containing the configured top-ranked Tranco domains.
- `RegexGenerator` uses this ordered Redis list when it needs benign
  high-reputation domains for domain-like regex testing.
- The number of domains kept in `tranco_top_domains` is configured with
  `whitelists.tranco_top_benign_limit`.

It also builds one in-memory bloom filter per benign type and one bloom filter
for generated regex hashes, but these do not replace the benign corpus scan.
They help with exact membership checks and future scale improvements, while the
acceptance decision still requires testing whether the regex matches any benign
string.

The current benign acceptance gate is:

```sql
SELECT value FROM benign_strings WHERE regex_type = ?
```

streamed line by line until the first match.

## Reading accepted regexes from other modules

Later modules should not open the SQLite files directly.

Use the DB helpers:

```python
self.db.get_generated_regexes(regex_type="dns_domain", limit=100)
self.db.get_generated_regexes_count(regex_type="dns_domain")
```

These helpers return accepted regexes by default.

## Offline coverage report

There is also a standalone offline report script for estimating how much the
accepted regexes cover several reference populations for a given Slips run.

Example:

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

The script writes:

- `regex_generator_coverage_report.html`
- `regex_generator_coverage_report.json`

inside the selected run output directory.

The estimate is based on:

- the RegexGenerator benign corpus DB, grouped by regex type
- the configured Tranco top benign domains from `whitelists.tranco_top_benign_limit` as extra benign data for domain-like types, when available in the Slips cache
- TI-derived malicious reference strings from Redis and TI cache files, grouped by regex type
- observed traffic strings from Zeek logs or `flows.sqlite`, grouped by regex type
- the per-type reference union, which is `malicious TI ∪ observed traffic`

This is an offline report only. It does not run continuously inside Slips.
