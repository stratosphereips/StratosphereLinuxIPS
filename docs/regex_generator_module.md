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
7. Stores accepted and rejected results in local SQLite

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
  generation_interval_seconds: 5
  allowed_backends: []
  llm_temperature: 1.2
  llm_max_tokens: 220
  llm_response_timeout_seconds: 90
  recent_history_size: 20
  max_regex_length: 180
  type_weights:
    dns_domain: 1
    uri: 1
    filename: 1
    tls_sni: 1
    certificate_cn: 1
  store_dir: output/regex_generator
  seed_benign_samples: true
```

Configuration reference:

- `enabled`: enables or disables the module.
- `generation_interval_seconds`: delay between completed generation cycles.
- `allowed_backends`: preferred backend aliases for this module.
- `llm_temperature`: generation temperature. Kept high to keep outputs varied.
- `llm_max_tokens`: max tokens for the LLM reply.
- `llm_response_timeout_seconds`: max time to wait for the matching
  `llm_response`.
- `recent_history_size`: number of recent same-type regexes included in the
  prompt as exclusions.
- `max_regex_length`: hard reject longer regexes.
- `type_weights`: weighted random choice among the supported regex types.
- `store_dir`: directory containing `benign_corpus.sqlite` and
  `generated_regexes.sqlite`.
- `seed_benign_samples`: seed the benign DB once with a small built-in sample.

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

The prompt requires the model to return strict raw JSON:

```json
{
  "regex": "...",
  "rationale": "short text"
}
```

V1 keeps one request in flight at a time, so response correlation is simple:
only the matching `request_id` is accepted.

## Acceptance pipeline

After the matching `llm_response` arrives, the module:

1. Parses the returned JSON object
2. Extracts `regex`
3. Rejects empty or malformed results
4. Applies static safety validation
5. Rejects exact duplicates already stored
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

It also builds one in-memory bloom filter per type, but the bloom filters do
not replace the benign corpus scan. They help with exact-string support and
future scale improvements, while the acceptance decision still requires testing
whether the regex matches any benign string.

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
