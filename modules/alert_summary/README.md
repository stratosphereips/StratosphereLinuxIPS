# Alert Summary Module

The `AlertSummary` module creates one analyst-facing summary paragraph for each
Slips alert.

It consumes `new_alert`, loads the correlated evidence records that caused the
alert, sends a structured prompt to the shared `LLM` module, and writes the
result to `output/alerts/alerts-summary.log`.

## What it does

For each alert, the module:

1. Receives the alert from the `new_alert` Redis channel.
2. Loads the evidence referenced by `alert.correl_id` from the current profile
   and time window.
3. Builds a prompt that asks the model to act as a senior cybersecurity
   researcher and incident analyst.
4. Publishes one request on `llm_request`.
5. Waits for the matching `llm_response` using `request_id`.
6. Normalizes the reply into one plain-text paragraph.
7. Appends the result to `output/alerts/alerts-summary.log`.

If no backend is available during shutdown, or if the LLM request times out,
the module writes a short failure note for that alert instead of blocking the
run indefinitely.

V1 keeps only one LLM request in flight at a time.

## Configuration

Example section in `config/slips.yaml`:

```yaml
alert_summary:
  enabled: false
  log_verbosity: 2
  allowed_backends: []
  llm_temperature: 0.2
  llm_max_tokens: 220
  llm_response_timeout_seconds: 120
```

Configuration reference:

- `enabled`: enables or disables the module.
- `log_verbosity`: controls how much operational detail is written to
  `<output-dir>/llm-summary/alert_summary.log`. Use `0` for an empty file,
  `1` for startup/failure summaries, `2` for per-alert request flow, and `3`
  for debug details.
- `allowed_backends`: preferred runtime-ready LLM backend aliases for this
  module. If empty, the module falls back to the shared LLM default backend.
- `llm_temperature`: sampling temperature. The default stays low to keep the
  summaries stable and restrained.
- `llm_max_tokens`: token budget for the summary paragraph.
- `llm_response_timeout_seconds`: hard timeout for one alert summary request.
  If set to `0`, the module waits indefinitely.

## Prompt and output contract

The system prompt tells the model to:

- act as a very professional and senior cybersecurity researcher and incident
  analyst
- use only the provided alert and evidence data
- return exactly one paragraph of plain text
- explain the suspicious behavior, the strongest supporting or weakening
  evidence, the likely true-positive or false-positive status, and the risk

The module sends:

- `requester = "alert_summary"`
- `messages`
- `temperature`
- `max_tokens`
- `metadata.alert_id`
- `metadata.profileid`
- `metadata.timewindow`
- `metadata.evidence_count`
- `metadata.prompt_version`

The summary file is:

```text
output/alerts/alerts-summary.log
```

Each line contains the alert time, source profile, alert ID, time window, and
the one-paragraph LLM summary.

The operational log file is:

```text
<output-dir>/llm-summary/alert_summary.log
```
