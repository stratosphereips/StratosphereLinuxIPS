# Alert Summary Module

The `AlertSummary` module creates a compact analyst-facing summary for every
Slips alert.

It listens for generated alerts, gathers the evidence that caused each alert,
queries the shared `LLM` module, and writes one paragraph per alert to
`output/alerts/alerts-summary.log`.

## What it does

For each alert, the module:

1. Receives the alert on `new_alert`.
2. Loads all evidence records referenced by `alert.correl_id`.
3. Builds a structured prompt using the alert and correlated evidence.
4. Discovers runtime-ready LLM backends with
   `self.db.get_available_llm_backends()`.
5. Publishes one request on `llm_request`.
6. Waits for the matching `llm_response`.
7. Normalizes the reply into one plain-text paragraph and appends it to the
   alert summary log.

If the configured timeout is reached, the module writes a short failure note
for that alert and continues with the next one. If Slips is already shutting
down and no LLM backend is runtime-ready, it flushes pending alerts with the
same kind of failure note instead of waiting forever.

V1 keeps only one LLM request in flight at a time.

## Configuration

Example section in `config/slips.yaml`:

```yaml
alert_summary:
  enabled: false
  allowed_backends: []
  llm_temperature: 0.2
  llm_max_tokens: 220
  llm_response_timeout_seconds: 120
```

Configuration reference:

- `enabled`: enables or disables the module.
- `allowed_backends`: preferred runtime-ready LLM backend aliases for this
  module. If empty, the module falls back to the shared LLM default backend.
- `llm_temperature`: low-temperature setting used to keep summaries stable and
  analyst-oriented.
- `llm_max_tokens`: output budget for the single summary paragraph.
- `llm_response_timeout_seconds`: hard timeout for a single alert summary
  request. If set to `0`, the module waits indefinitely.

## Prompt design

The module uses a fixed system prompt that asks the model to behave like a very
professional and senior cybersecurity researcher and incident analyst.

The prompt explicitly requires the model to:

- use only the supplied alert and evidence context
- return exactly one paragraph of plain text
- explain the main suspicious behavior
- identify the evidence that most strongly supports or weakens the alert
- assess whether the alert is likely true positive, likely false positive, or
  uncertain
- state the likely operational risk
- avoid inventing missing facts

The user prompt includes a compact JSON view of:

- the alert ID, profile, time window, confidence, and threat level
- the correlated evidence count
- every linked evidence record, including description, timing, confidence,
  evidence signal, ports, attacker data, and victim data when available

## Shared LLM integration

The module uses the existing shared LLM contract:

- request channel: `llm_request`
- response channel: `llm_response`

Each request contains:

- `request_id`
- `requester = "alert_summary"`
- `backend`
- `messages`
- `temperature`
- `max_tokens`
- `metadata.alert_id`
- `metadata.profileid`
- `metadata.timewindow`
- `metadata.evidence_count`
- `metadata.prompt_version`

The module accepts only the response whose `request_id` matches the active
pending alert summary request.

## Output file

Summaries are written to:

```text
output/alerts/alerts-summary.log
```

Each alert produces one line containing:

- the alert time
- the source IP, and hostname if available
- the alert ID
- the time window number
- the one-paragraph LLM summary

If summary generation fails, the same file records a short unavailability
message for that alert instead.
