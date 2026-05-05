# How the Slips Alert Summary Method Works

Slips already detects suspicious behavior and correlates multiple findings into
one alert. The alert summary layer is the part that turns that correlated
evidence into a short explanation that a human can read quickly.

This is not a general-purpose chatbot feature. It is a tightly scoped method
for translating one structured IDS alert into one evidence-bound analyst
paragraph.

## The Core Idea

The method starts from a simple observation: an IDS alert is often technically
correct, but still hard for a person to consume.

One alert may contain many repeated detections:

- connections to many similar destinations
- repeated attempts on the same port
- several evidence records that describe the same behavior in slightly
  different wording

If all of that is passed to a language model as raw text, the result is waste,
noise, and unstable output. The method therefore has to do real engineering
before the model sees anything.

The alert summary process has five stages:

1. reconstruct the full correlated evidence set behind the alert
2. collapse repetitive evidence into a compact incident digest
3. retrieve recent alert history for the same source as extra context
4. build a constrained analyst-oriented prompt
5. reduce oversized alerts recursively when needed
6. generate one plain-text summary with a local fine-tuned model

That is the method.

## 1. Reconstruct the Whole Alert, Not Just the Final Label

The summary process does not start from a final verdict string. It starts from
the correlated evidence that Slips already attached to the alert.

Yes: the method uses the alert and all of its related evidence records.

That matters because a good explanation depends on:

- what behaviors were observed
- how often they happened
- how they were distributed over time
- which pieces of evidence are strong
- which pieces of evidence weaken confidence

So the method first rebuilds the alert context from the correlated evidence set
and orders it by time. If the full set is incomplete, it still falls back to
the most recent evidence so the alert is never left without context.

This keeps the summarizer tied to the actual IDS evidence instead of turning it
into a free-form text generator.

In practical terms, the alert carries the identifiers of the evidence records
that belong to it. The summarization layer uses those identifiers to fetch the
full correlated evidence set for that source IP and time window, then selects
the evidence records referenced by that alert.

So the context is not:

- one title
- one severity
- one last event

The context is:

- the alert metadata
- the full set of evidence records linked to that alert
- their timestamps
- their descriptions
- their severities
- the threat level and confidence already computed by Slips

Example:

```text
Alert:
- Source IP: 192.168.1.113
- Time window: 8
- Threat level: 15.1
- Confidence: 0.84
- Related evidence IDs: 31 records

Related evidence:
- 07:00 Horizontal port scan to 443/TCP from 192.168.1.113 to 5 unique IPs
- 07:02 Connection to unknown destination port 449/TCP to 76.16.105.16
- 07:03 Connection to unknown destination port 449/TCP to 177.251.27.6
- 07:10 Connection to unknown destination port 449/TCP to 209.205.188.238
- ...
```

That full correlated set is what the summary method works from.

## 2. Collapse Repetition into Incident Patterns

This is the most important part of the method.

Security alerts are usually repetitive. The same basic event can appear many
times with only a changed IP address, port number, or counter. A small local
model should not waste context reading fifty versions of the same pattern.

The method therefore groups similar evidence descriptions together after
normalizing variable fields.

In practice, this means:

- IP addresses are abstracted into placeholders
- port expressions are abstracted into placeholders
- raw counts are abstracted into placeholders

After normalization, descriptions that represent the same underlying behavior
collapse into one group.

Example of normalization:

```text
Before:
- Connection to unknown destination port 449/TCP to 76.16.105.16
- Connection to unknown destination port 449/TCP to 177.251.27.6
- Connection to unknown destination port 449/TCP to 209.205.188.238

Normalized pattern:
- Connection to unknown destination port <PORT>/TCP to <IP>
```

For each group, the method keeps the details that matter operationally:

- the time range of the group
- one representative behavior description
- how many similar records belong to that group
- the severity mix inside the group
- a few sample IPs or ports when examples are useful

The result is no longer a flat list of events. It becomes an incident digest:
a short list of dominant behavior patterns, ordered by importance.

Example of a grouped digest:

```text
- 07:02-07:22 | Connection to unknown destination port 449/TCP
  (21x similar, severities: medium=21, samples: 76.16.105.16, 177.251.27.6, 209.205.188.238, 449/TCP)
- 07:00-07:03 | Horizontal port scan to port 443/TCP
  (2x similar, severities: high=2, samples: 443/TCP)
```

This is the main reason the summary layer works well with local models. It
removes repetition without removing the shape of the incident.

## 3. Build a Constrained Analyst Prompt

The current alert is no longer summarized in isolation.

Before the final prompt is built, the method can retrieve a bounded memory of
recent prior alerts for the same source or profile. That history is not the new
evidence itself. It is supporting context that helps answer questions such as:

- is this a continuation of the same activity?
- is the behavior escalating?
- is the source expanding into new patterns?
- does the current alert look isolated or part of a sequence?

The history kept for each prior alert is compact. It includes:

- the time window and time range
- the accumulated threat level
- the alert confidence
- a few dominant grouped patterns
- the final summary text of that earlier alert

Example of recent history context:

```text
Recent alert history:
- TW 6 | 08:00-09:00 | threat=9.20 | conf=0.76 |
  top patterns: Horizontal port scan to port 443/TCP;
  repeated unknown-port traffic |
  prior summary: Earlier scanning activity suggests reconnaissance.

- TW 7 | 09:00-10:00 | threat=12.40 | conf=0.81 |
  top patterns: Repeated connections to unknown destination port 449/TCP |
  prior summary: The source continued unusual outbound probing across multiple
  external IPs.
```

That history is then added to the final prompt as context only. The current
alert evidence remains the primary source of truth.

## 4. Build a Constrained Analyst Prompt

Once the incident digest exists, the method builds a prompt that is narrow,
structured, and conservative.

The prompt contains two kinds of information.

First, it provides metadata about the alert:

- source IP
- time window
- time range
- accumulated threat level
- alert confidence
- number of correlated evidence records
- number of grouped evidence patterns
- number of reduction layers already applied

Second, when available, it provides the recent alert history for the same
source/profile.

Third, it provides the evidence digest itself: the grouped incident patterns
described above.

Then it asks for a very specific output:

- explain the main suspicious behavior
- identify the strongest supporting or weakening evidence
- say whether the alert looks likely true positive, likely false positive, or
  uncertain
- state the likely operational risk or urgency
- explain whether the current alert looks like a continuation, escalation,
  diversification, or a different pattern relative to recent activity

The output is constrained to one paragraph of plain text.

This is important. The system is not asking for a report, bullets, JSON, or
creative prose. It is asking for one concise analyst paragraph that can sit
next to the alert.

So if the question is "what exactly is the context and what exactly is the
question?", the answer is:

The context is the alert metadata plus the grouped digest of all evidence
linked to that alert, plus recent prior summarized alerts for the same source
when history is available.

The question is essentially:

```text
Here is one Slips alert with its correlated evidence.
Here is recent alert history for the same source, if available.
Explain the main suspicious behavior.
Identify what evidence most strongly supports or weakens the alert.
Say whether it looks likely true positive, likely false positive, or uncertain.
State the likely operational risk.
Explain whether this looks like a continuation, escalation, diversification, or
a different pattern relative to recent activity.
Write exactly one plain-text paragraph.
Use only the provided data.
Do not invent missing facts.
```

Example of prompt context:

```text
Incident metadata:
- Source IP: 192.168.1.113
- Time window: 8
- Time range: 07:00 to 07:22
- Threat level: 15.1
- Confidence: 0.84
- Correlated evidence records: 31
- Grouped evidence patterns: 2

Evidence digest:
- 07:02-07:22 | Connection to unknown destination port 449/TCP (21x similar)
- 07:00-07:03 | Horizontal port scan to port 443/TCP (2x similar)

Recent alert history:
- TW 7 | 06:00-07:00 | threat=8.70 | conf=0.71 | top patterns: repeated
  unknown-port traffic | prior summary: Earlier unusual outbound probing was
  already observed from the same source.
```

Example of the kind of answer the method is trying to produce:

```text
This alert shows repeated connections from 192.168.1.113 to an unusual
destination port 449/TCP across multiple external IPs, together with a
horizontal scan to port 443/TCP, which makes the activity look more consistent
with reconnaissance than with a single benign connection. The repeated pattern
and high-severity scan evidence strengthen the alert, and the recent alert
history suggests this is a continuation and escalation of earlier probing from
the same source. Although the absence of host-side context leaves some
uncertainty, this looks like a likely true positive and should be treated as
medium-to-high operational risk.
```

## 5. Guard the Model Against Hallucinations

Using an LLM inside an IDS only makes sense if the output is grounded.

The summary method adds several guardrails before and during generation:

- the prompt explicitly says to use only the provided alert and evidence data
- the prompt explicitly says not to invent missing facts
- the output is restricted to one paragraph
- repetitive evidence is grouped before inference so the model sees a cleaner
  representation of the incident
- uncertainty is required when the evidence is weak, incomplete, or
  contradictory
- the generation temperature is kept low to reduce drift

This does not mean hallucinations are impossible. It means the method is built
to make them less likely, easier to detect, and less operationally dangerous.

The training pipeline also helps here. The local models were not trained on
random free-form responses. They were trained on selected, higher-quality
security summaries derived from real Slips incidents. That gives the model a
much tighter target behavior.

## 6. Control the Context Budget Explicitly

Small local models are useful only if the input stays under control.

The method therefore estimates prompt size explicitly and uses separate budgets
for:

- recent alert history
- the final analyst summary prompt
- intermediate reduction prompts
- the final answer length

This is not cosmetic. It is required for reliable local deployment.

If the grouped digest already fits inside the final prompt budget, the model is
called directly.

If it does not fit, the method does not simply cut the alert in half and hope
for the best. Instead, it performs recursive evidence reduction.

The history itself is also bounded. Only a small number of recent alerts are
kept per source/profile, and only a bounded token budget is reserved for that
history in the final prompt. This prevents memory from growing into prompt
pollution.

## 7. Use Recursive Reduction Instead of Blind Truncation

When an alert is too large, the evidence digest is split into smaller chunks.
Each chunk is summarized into a shorter intermediate digest, and those
intermediate digests are then combined into the next layer.

This can repeat several times until the final prompt fits.

The reduction step is carefully scoped:

- it preserves behaviors, time ranges, counts, and suspicious indicators
- it preserves false-positive clues
- it is not allowed to make the final verdict for the whole alert

If one digest item is still too large by itself, it is split at natural
boundaries:

- line boundaries
- semicolons
- sentence breaks
- commas
- finally words if necessary

This matters because it keeps the reduction process information-preserving.
Instead of throwing evidence away, the method compresses it layer by layer.

Example:

```text
Original digest:
- 18 grouped items covering scans, repeated unknown-port traffic, DNS failures,
  TLS anomalies, and HTTP evidence

Reduction layer 1:
- chunk 1 summary: dominant scanning and unknown-port behavior
- chunk 2 summary: DNS and TLS anomalies
- chunk 3 summary: HTTP and supporting evidence

Final prompt:
- 3 reduced digest items instead of the original 18
```

That is a much stronger design for security alerts than naive truncation.

## 8. Use a Shared Local Model Service

The alert summary layer does not hard-code one model API into the summarization
logic.

Instead, it sends requests through a shared model service that all AI-enabled
parts of Slips can use. That service is responsible for:

- backend selection
- queueing
- worker concurrency
- request tracking
- response delivery

This separation is important for engineering quality.

It means the alert summary method can stay focused on:

- evidence reconstruction
- grouping
- prompt design
- reduction
- fallback behavior

while the model service handles transport and backend management.

It also means Slips can expose several local model variants with different
speed and quality tradeoffs without changing the summary method itself.

## 9. Prefer Local Fine-Tuned Models

For this use case, local models are the right default.

The reasons are practical:

- alert data stays inside the monitored environment
- the feature works offline
- the cost is predictable
- deployment is possible on the same systems where Slips already runs

This is especially relevant for edge deployments. Slips was designed to support
local inference even on constrained hardware, which is why model size,
quantization, context budget, and prompt efficiency matter so much in this
method.

The summary layer also benefits directly from fine-tuning. General-purpose
models are not optimized for compact, evidence-bound security explanations.
Fine-tuned local models are better aligned with the actual task:

- summarize correlated alerts
- reason about supporting and weakening evidence
- express uncertainty correctly
- stay concise under tight context limits

The public fine-tuning pipeline behind these models used real Slips incidents,
best-of-N supervision, and judge-based selection to create higher-quality
training targets. The result is a family of local models specialized for alert
summary and risk-oriented security analysis.

## 10. Match Replies Strictly

In a shared model architecture, many requests may be in flight at once. The
summary method therefore tracks each request with its own unique identifier and
accepts only the matching reply.

This is a simple but critical detail.

Without strict reply matching, one module could accidentally consume another
module's response. In a security system, that would be unacceptable.

By keeping one active summary request at a time and matching replies
explicitly, the method stays deterministic and auditable.

## 11. Fail Safely When the Model Is Unavailable

An IDS cannot simply return nothing because a model times out.

So the summary layer includes a local fallback path.

If the model request fails, the method still produces one paragraph based on:

- the strongest grouped indicators
- the severity distribution
- the alert confidence
- the accumulated threat level
- recent alert history when available

This fallback is intentionally simpler than the model output, but it preserves
an essential property: every alert still gets an explanation.

Example fallback style:

```text
LLM summary unavailable. Local heuristic summary: this alert correlates 31
evidence records for one source IP, with the strongest indicators being
repeated connections to an unknown destination port and a horizontal scan to
443/TCP. The evidence mix includes high and medium severity findings. Based on
the accumulated threat level and confidence, this looks like a likely true
positive and the operational risk appears medium to high.
```

That is the correct design choice for an operational security tool.

## 12. Shut Down Without Dropping Explanations

Another subtle part of the method is shutdown behavior.

If the system is stopping while a model request is still in flight, the summary
layer does not immediately abandon that request. It waits for the shared model
service to finish delivering the reply.

Only if it truly cannot complete the request does it flush the alert with the
fallback paragraph.

This protects against a common failure mode in asynchronous systems: the model
finishes, but the caller has already exited, so the answer is lost.

For an IDS, losing the explanation even though the alert exists is a real
operational bug. The method is designed to avoid that.

## 13. Why This Improves Explainability

The real value of the summary layer is not that it adds AI to an IDS.

The real value is that it improves the last mile of human consumption.

Slips already knows a lot about an incident. What this method adds is a bridge
from machine evidence to human understanding.

That improves:

- analyst triage speed
- clarity of why an alert matters
- explainability for non-specialists
- usability of a behavioral IDS in practice

Instead of forcing the human to read a large correlated evidence set, the
system provides one evidence-bound explanation that can be read in seconds.

## 14. Why This Matters Beyond Slips

To our knowledge, Slips is the first IDS deployed with a local model
fine-tuned specifically for security analysis of alerts.

That matters because it shows a different path for AI in security.

The interesting contribution is not "an IDS that can call a model." The
interesting contribution is this combination:

- local inference
- fine-tuned security-specific models
- structured evidence compression
- recursive reduction for large incidents
- explicit anti-hallucination guardrails
- analyst-facing explanations

That is a real method, not a demo.

## Final Thought

The alert summary layer is a narrow, technical, and carefully engineered piece
of Slips.

It reconstructs the correlated evidence behind an alert, compresses repetition
into incident patterns, adds bounded recent-history context, controls the
prompt budget, uses recursive reduction when needed, and generates one
grounded explanation with a local fine-tuned model.

That is why it works. And that is why this feature is useful.
