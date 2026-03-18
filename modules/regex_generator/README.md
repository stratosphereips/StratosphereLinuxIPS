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
10. Stream the benign corpus for that type and stop on the first match.
11. Store accepted regexes in SQLite. Rejected regexes are only persisted if
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
corpus for the selected type and rejects the regex on the first benign match.

## Benign corpus and bloom filters

The module creates a dedicated benign corpus DB once and can seed it with a
small built-in sample for all supported types.

On each run, it also imports domain entries from the configured Slips local
whitelist file into the benign corpus for the matching domain-like regex
types:

- `dns_domain`
- `tls_sni`
- `certificate_cn`

It builds one in-memory bloom filter per benign type and one additional bloom
filter for generated regex hashes. These filters speed up exact membership
checks, but they do not replace the benign corpus scan. Acceptance still
requires checking whether a regex matches any benign string.

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
[37/752] type=dns_domain comparisons=742257/8547616 regex=...
```

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

- `--full-scan`: disable sampling and scan the full populations.
- `--max-population-size`: sample cap for each population/type in estimate mode.
- `--match-timeout-seconds`: per-regex/per-population timeout guard.

This generates:

- `regex_generator_coverage_report.html`
- `regex_generator_coverage_report.json`

inside the selected run output directory.

The report estimates coverage against:

- the local benign corpus DB
- TI-derived malicious reference strings from Redis and TI files
- observed traffic strings from the same run, taken from Zeek logs or
  `flows.sqlite`

The report is offline only. It is not part of the continuous RegexGenerator
loop.
