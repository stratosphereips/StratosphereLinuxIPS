# Alert Summary Module

The `AlertSummary` module creates one analyst-facing summary paragraph for each
Slips alert.

It listens for `new_alert`, loads the correlated evidence that triggered the
alert, uses the shared `LLM` module to build an analyst summary, and writes the
result to `output/alerts/alerts-summary.log`.

## What it does

For each alert, the module:

1. Receives the alert from `new_alert`.
2. Loads every evidence record referenced by `alert.correl_id`.
3. Groups similar evidence descriptions into an incident-style digest.
4. Estimates whether the grouped digest fits the prompt budget.
5. If it fits, sends the final analyst-summary request to `llm_request`.
6. If it does not fit, recursively reduces the digest through one or more
   intermediate LLM summaries until the final prompt fits.
7. Waits for the matching `llm_response`.
8. Writes one plain-text paragraph per alert to `output/alerts/alerts-summary.log`.

If the LLM pipeline fails, the module writes a local heuristic fallback summary
instead of leaving the alert without analyst context.

The module can also keep a bounded recent-history memory per source/profile.
When enabled, that history is added to the final analyst-summary prompt as
extra context so the current alert can be explained relative to recent past
activity instead of being summarized in isolation. When the current alert
matches repeated prior alerts, that recurrence is intended to act as
cumulative supporting context that can raise confidence and urgency.

## Recursive reduction

The module now follows the incident-style prompt design used in
`Slips-tools/alert_summary/inference.py`, but adapts it to live Slips alerts.

When an alert is too large for the final prompt budget, the module does not
truncate the evidence. Instead it:

1. Groups similar evidence lines.
2. Splits the grouped digest into chunks that fit a reduction prompt.
3. Requests one intermediate summary per chunk.
4. Repeats that reduction on the summaries if the combined digest is still too
   large.
5. Sends the reduced digest to the final analyst-summary prompt.

If one grouped line is still too large, the module splits it into multiple
segments on sentence or word boundaries so the full content is preserved.

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
  history_enabled: false
  history_max_alerts: 3
  history_max_tokens: 700
  history_patterns_per_alert: 2
```

Configuration reference:

- `enabled`: enables or disables the module.
- `log_verbosity`: controls how much operational detail is written to
  `<output-dir>/llm-summary/alert_summary.log`. Use `0` for an empty file,
  `1` for startup, shutdown, and failures, `2` for per-alert request flow,
  and `3` for prompt-budget and reduction-layer details.
- `allowed_backends`: preferred runtime-ready LLM backend aliases for this
  module. If empty, the module falls back to the shared LLM default backend.
- `llm_temperature`: low-temperature setting used to keep summaries stable and
  analyst-oriented.
- `llm_max_tokens`: output budget for the final analyst paragraph.
- `llm_response_timeout_seconds`: hard timeout for one in-flight shared-LLM
  request. If set to `0`, the module waits indefinitely.
- `history_enabled`: keeps recent prior alert summaries in memory and adds
  them to the final prompt for the same source/profile.
- `history_max_alerts`: maximum number of prior summarized alerts kept per
  source/profile.
- `history_max_tokens`: approximate token budget reserved for recent-history
  context inside the final prompt.
- `history_patterns_per_alert`: number of dominant grouped evidence patterns
  stored from each prior alert.

## Prompt design

The final prompt is built around:

- incident metadata
- recent alert history for the same source/profile when enabled
- grouped evidence patterns with time ranges, counts, severities, and samples
- instructions to explain the suspicious behavior, strongest supporting or
  weakening evidence, likely true-positive or false-positive status,
  operational risk, and whether the current alert looks like a continuation,
  escalation, repetition, diversification, or a different pattern relative to
  recent past activity

Intermediate reduction prompts use the same incident metadata but ask the model
to compress one evidence chunk into a shorter digest for the next reduction
layer or the final summary.

## Recent alert history

When `history_enabled` is on, the module stores a small in-memory history of
completed alert summaries per source/profile. Each stored entry contains:

- time window and compact time range
- accumulated threat level
- alert confidence
- a few dominant grouped evidence patterns
- the final summary text

That history is added only to the final analyst-summary prompt, not to
intermediate reduction prompts. The current alert evidence remains the primary
source of truth, but repeated aligned alerts are meant to be treated as
cumulative supporting context. In other words, recurrence should not replace
the current alert evidence, but it can strengthen the assessment of risk,
urgency, and likely true-positive status when the current alert matches the
historical pattern.

## Shared LLM integration

The module uses the shared LLM contract:

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
- `metadata.grouped_item_count`
- `metadata.reduction_layer`
- `metadata.prompt_version`

Reduction requests also include `metadata.chunk_index` and
`metadata.chunk_count`.

## Logs and output

Analyst summaries are written to:

```text
output/alerts/alerts-summary.log
```

Alert-summary operational logs are written to:

```text
<output-dir>/llm-summary/alert_summary.log
```

Shared LLM runtime logs are written to:

```text
<output-dir>/LLM/llm.log
```

The alert-summary log records queueing, prompt-budget decisions, reduction
layers, request publication, replies, failures, and shutdown handling.

## Shutdown behavior

The module keeps waiting during shutdown while a shared LLM request is still
in flight. This prevents the old race where the shared `LLM` module finished
later and published a reply after `alert_summary` had already exited.
