# Alert Summary Module

The `AlertSummary` module creates one analyst-facing summary paragraph for every Slips alert.

It listens for generated alerts, gathers the evidence that caused each alert, queries the shared `LLM` module, and writes one summary line per alert to `output/alerts/alerts-summary.log`.

## What it does

For each alert, the module:

1. Receives the alert on `new_alert`.
2. Loads all evidence records referenced by `alert.correl_id`.
3. Groups similar evidence descriptions into an incident-style digest.
4. Estimates whether the digest fits the final prompt budget.
5. Sends either the final summary prompt or one reduction prompt on
   `llm_request`.
6. Waits for the matching `llm_response`.
7. Repeats reduction layers as needed until the final prompt fits.
8. Normalizes the last reply into one plain-text paragraph and appends it to
   the alert summary log.

If the LLM pipeline fails, the module writes a local heuristic fallback summary
for the alert instead of leaving the run without output.

## Recursive summary hierarchy

This module follows the prompt style from `https://github.com/stratosphereips/Slips-tools/alert_summary/inference.py` as per the original specifgication, but it is completely implemented and adapted to live Slips alerts in this module.

When the grouped evidence is too large for the final prompt, the module does
not truncate it. It performs a hierarchy of summaries instead:

1. Split the grouped digest into prompt-sized chunks.
2. Ask the shared LLM for one intermediate digest per chunk.
3. If the combined chunk digests are still too large, split and summarize
   them again.
4. Send the reduced digest to the final analyst-summary prompt.

If one grouped line is too large by itself, it is split on sentence or word
boundaries so the content is preserved without clipping.

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
  `1` for startup, shutdown, and failures, `2` for per-alert queueing and
  request flow, and `3` for prompt-budget and reduction-layer details.
- `allowed_backends`: preferred runtime-ready LLM backend aliases for this
  module. If empty, the module falls back to the shared LLM default backend.
- `llm_temperature`: low-temperature setting used to keep summaries stable and
  analyst-oriented.
- `llm_max_tokens`: output budget for the final analyst paragraph.
- `llm_response_timeout_seconds`: hard timeout for one in-flight shared-LLM
  request. If set to `0`, the module waits indefinitely.

## Prompt design

The final prompt contains:

- alert metadata
- grouped evidence patterns with time ranges, counts, severities, and sample
  IPs or ports
- instructions to explain the suspicious behavior, strongest supporting or
  weakening evidence, likely alert validity, and operational risk

Reduction prompts reuse the same alert metadata but ask the model to compress
one chunk into a shorter intermediate digest for the next reduction layer.

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
- `metadata.grouped_item_count`
- `metadata.reduction_layer`
- `metadata.prompt_version`

Reduction requests also include `metadata.chunk_index` and
`metadata.chunk_count`.

The module accepts only the response whose `request_id` matches the active
in-flight request.

## Output files

Analyst summaries are written to:

```text
output/alerts/alerts-summary.log
```

Operational logs for this module are written to:

```text
<output-dir>/llm-summary/alert_summary.log
```

Operational logs for the shared LLM backend are written to:

```text
<output-dir>/LLM/llm.log
```

The alert-summary log records queueing, prompt-budget checks, reduction-layer
progress, request publication, replies, failures, and shutdown handling.

## Shutdown behavior

The module keeps waiting during shutdown while a shared LLM request is still
in flight. That prevents the old race where the shared `LLM` module finished
later and published a reply after `alert_summary` had already exited.
