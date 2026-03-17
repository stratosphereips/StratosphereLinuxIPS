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
- `allowed_backends`: preferred LLM backend aliases for this module.
- `llm_temperature`: generation temperature. Kept high to encourage variation.
- `llm_max_tokens`: max tokens for the LLM reply.
- `llm_response_timeout_seconds`: max time to wait for the matching
  `llm_response`.
- `recent_history_size`: number of recent same-type regexes included in the
  prompt as "do not repeat" history.
- `max_regex_length`: hard reject longer regexes.
- `type_weights`: weighted random choice among the five regex types.
- `store_dir`: directory containing `benign_corpus.sqlite` and
  `generated_regexes.sqlite`.
- `seed_benign_samples`: seed the benign DB once with a small built-in sample.

## Runtime flow

Each cycle does this:

1. Discover runtime-ready LLM backends with
   `self.db.get_available_llm_backends()`.
2. Choose one backend alias from `allowed_backends`, or fall back to the LLM
   default backend.
3. Choose the next regex type using weighted random selection.
4. Build a fixed prompt for that type, including recent regex history.
5. Publish one request on `llm_request`.
6. Wait for the matching `llm_response` using `request_id`.
7. Extract the regex from the returned JSON.
8. Apply static safety validation.
9. Stream the benign corpus for that type and stop on the first match.
10. Store the result as accepted or rejected.

V1 keeps only one LLM request in flight at a time.

## LLM contract

Request payload:

```json
{
  "request_id": "RegexGenerator-...",
  "requester": "RegexGenerator",
  "backend": "local_qwen",
  "messages": [...],
  "temperature": 1.2,
  "max_tokens": 220,
  "metadata": {
    "regex_type": "dns_domain",
    "prompt_version": "regex-generator-v1",
    "generation_nonce": "..."
  }
}
```

The prompt requires the model to return strict raw JSON:

```json
{
  "regex": "...",
  "rationale": "short text"
}
```

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

After static validation, the module scans the benign corpus for the selected
type and rejects the regex on the first benign match.

## Benign corpus and bloom filters

The module creates a dedicated benign corpus DB once and can seed it with a
small built-in sample for all supported types.

It also builds one in-memory bloom filter per type, but the bloom filters do
not replace the benign corpus scan. Bloom filters can answer exact-string
membership questions, while acceptance requires checking whether a regex matches
any benign string.

## Stored regexes

Accepted and rejected regexes are stored in `generated_regexes.sqlite`.

Other modules should access accepted regexes through:

```python
self.db.get_generated_regexes(regex_type="dns_domain", limit=100)
self.db.get_generated_regexes_count(regex_type="dns_domain")
```

These helpers read accepted regexes by default.
