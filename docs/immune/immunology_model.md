# Immunology-inspired model for Slips

## Scope and sources

This document describes, at the model level, how Slips Immune uses immunology as an architectural reference. The main source is the draft paper "Rethinking the Principles of Immunity For a Cybersecurity Immune System" (`Rethinking_the_Principles_of_Immunity_For_a_Cybersecurity_Immune_System. Draftv1.pdf`). The paper emphasizes coordinated detection, communication, and regulation, rather than isolated detector mechanisms.

The text below stays generic and avoids binding the model to specific Slips modules. For an implementation-oriented description, see [Architecture Design of Slips Immune](immune_architecture.md).

## Rationale

The biological immune system is not a single detector. It is a layered and regulated defense system. Several properties are useful as design constraints for IDS/IPS systems:

- Layering with distinct trade-offs between latency and precision.
- Multi-signal activation before high-impact responses.
- Context propagation that supports later validation and correlation.
- A detector lifecycle that includes creation, evaluation, retention, and removal.
- Regulation of response magnitude and duration, including explicit termination.
- Distributed coordination without a single mandatory control point.

These constraints target a common operational problem: detection must be fast, but high-cost actions must be resistant to false positives.

## Core abstractions

Slips can be described using four abstractions that map well to immunology-inspired language:

1. Signals. Compact messages describing observations and their severity.
2. Detectors. Mechanisms that generate and validate signals.
3. Effectors. Actions that reduce harm or limit propagation.
4. Regulators. Logic that controls escalation, de-escalation, and termination.

The resulting control loop is:

1. Generate signals from observations.
2. Attach evidence and context.
3. Correlate signals across time and across hosts.
4. Escalate to stronger detectors and stronger actions when warranted.
5. Downregulate to baseline when the episode resolves.

## Layered defense

### Innate layer

In immunology, innate responses are fast, generic, and biased toward containment. They operate with limited specificity and can tolerate a higher error rate because their actions are bounded.

In Slips, the innate layer corresponds to:

- Low-latency detection of broadly malicious properties.
- Initial containment actions whose failure modes are acceptable, for example temporary blocks with short time-to-live, rate limits, or increased telemetry.
- Emission of standardized signals that can be shared and combined.

The innate layer is not expected to be definitive. It prioritizes speed and coverage.

### Adaptive layer

In immunology, adaptive responses are slower, more specific, and potentially more damaging if misapplied. They are therefore gated and regulated. Adaptive mechanisms also include memory.

In Slips, the adaptive layer corresponds to:

- Detectors with high specificity and stronger acceptance criteria.
- Detector generation and refinement from confirmed episodes.
- Retention of effective detectors as memory, with explicit capacity control.
- Feedback that changes the behavior of the innate layer, for example by suppressing repeated low-value alerts or by increasing sampling and evidence collection.

The adaptive layer is the natural place for high-impact actions, but only under high confidence and explicit policy constraints.

## Signal classes and context

The paper distinguishes two signal families that are useful in cybersecurity.

### PAMP-like signals

PAMP-like signals are tied to properties of an attack technique. In practice, this includes artifacts that are close to identity, such as specific protocol patterns, known tool behavior, exploit traces, or stable indicators of compromise.

PAMP-like signals provide specificity. They can be evaded or absent for novel attacks, but when present they support strong attribution to a technique.

### DAMP-like signals

DAMP-like signals reflect stress, damage, or loss of integrity. They measure consequences rather than identity. In practice, they correspond to anomaly-like signals: deviations from stable baselines, unusual volumes, unusual sequences, or behavioral shifts that are not unique fingerprints of one attack.

DAMP-like signals support novelty and impact assessment. They are also the natural place where concept drift can appear and must be managed.

### Context and evidence

Signals without context are hard to validate and hard to automate safely. Slips treats context as part of the incident record, not as a post-processing step. Typical context includes:

- Origin of the observation, including host and vantage point.
- Time bounds and persistence.
- Neighboring activity that can act as supporting evidence.
- Confidence values and detector provenance, such as thresholds or model versions.
- Response constraints derived from environment policy and asset criticality.

Context enables correlation and helps separate repeated benign patterns from repeated malicious behavior.

## Activation and escalation

The main safety principle in the paper is multi-signal activation. High-impact actions should not rely on a single evidence source.

In Slips this becomes a policy constraint:

- Fast containment can be triggered by one strong signal.
- Disruptive actions require at least two independent confirmations, typically one PAMP-like and one DAMP-like.

Independence is critical. If the same underlying data produces both signals, multi-signal activation degenerates into single-signal activation.

An escalation ladder follows naturally:

1. Evidence enrichment. Increase telemetry, bind observations into an episode.
2. Low-impact containment. Rate limits, short TTL blocks, friction, higher logging.
3. Confirmed response. Longer isolation actions under multi-signal activation.
4. Resolution. Controlled rollback and continued monitoring until stability is restored.

The response phase has a start condition and a termination condition. Without termination, the system accumulates permanent blocks, permanent escalation, and chronic alert fatigue.

## Detector lifecycle

The paper describes immunity as a system with detector creation, evaluation, amplification, and retention. The same structure is useful for Slips.

### Detector generation

Detector generation is driven by confirmed episodes. The output is a set of candidate detectors that cover a narrow neighborhood of the episode, for example variants of a pattern match, variants of a behavioral description, or variants of a correlation rule.

Generation is hypothesis creation. It does not imply acceptance.

### Evaluation and negative selection

Negative selection is the main safety gate. Candidate detectors are evaluated against representative benign data and expected operational patterns. Unacceptable false positives are rejected or the detector is constrained to narrower contexts.

Unlike biology, cybersecurity can retain large benign corpora and rerun evaluation repeatedly. This should be used. Re-evaluation after refinement is required because refinement can widen matching conditions.

### Refinement

Clonal selection in the paper is best read as a constraint: refinement should increase specificity, not generality. A refined detector should:

- Match the episode strongly.
- Match benign baselines weakly or not at all.
- Carry explicit context constraints when applicable, for example protocol, directionality, and asset class.

### Memory and retirement

Memory retains effective detectors and accelerates response to similar episodes. Memory should be bounded and continuously assessed:

- Capacity limits and time-to-live prevent unbounded growth.
- Performance tracking identifies detectors that drift into false positives.
- Deactivation and narrowing are explicit mechanisms for detectors that become unreliable.

This is an engineering analogue of immune tolerance and anergy. It prevents long-term accumulation of stale detectors.

## Response policy and regulation

Immunology provides useful language for response control: proportionality, exceptions, and resolution.

### Proportional actions

Security responses form a spectrum. Slips uses graded responses where possible:

- Throttling or shaping traffic before blocking.
- Short-lived blocks before persistent blocks.
- Step-up authentication or reduced privileges before account disablement.
- Escalated logging and inspection under increasing suspicion.

Graded response reduces outage risk when signals are ambiguous.

### Exceptions and safety constraints

Immunity has strong notions of tolerance. In Slips, the equivalent is explicit policy control:

- Maintenance windows and controlled suppression during incident response.
- Allowlisting for known-safe but noisy patterns, while keeping observation active.
- Asset-aware policy that limits actions on safety-critical or production systems.

These controls must be explicit and auditable. Silent exceptions create blind spots.

### Regulation and resolution

Regulation includes both activation and termination.

- Activation regulation uses thresholds, correlation, timers, and ensemble logic to delay escalation until evidence is coherent.
- Termination regulation reduces defense intensity when the episode resolves: blocks expire, elevated telemetry returns to baseline, and memory is updated.

Long-lived escalation without evidence is treated as a failure mode, analogous to chronic inflammation.

## Distributed coordination

The paper highlights communication as central to immune behavior. In cybersecurity, coordination supports multi-host correlation and safer automation.

At the model level, Slips uses communication to:

- Share PAMP-like and DAMP-like signals among peers.
- Share episode context for corroboration and refutation.
- Share de-escalation signals when the episode disappears from multiple vantage points.

This provides a mechanism for distributed confirmation and distributed resolution.

The paper also discusses the idea of making threats easier to eliminate by marking. In cybersecurity, marking must be constrained because attackers can spoof it. A practical analogue in controlled environments is tagging:

- Tag entities such as IPs, domains, hosts, or sessions with episode identifiers and suspicion levels.
- Propagate tags to align downstream actions, for example firewall policy and monitoring priority.

Tagging is not an "evil bit". It is an internal coordination tool with explicit trust boundaries.

## Observability

The paper uses the concept of "windows" into cell state. In cybersecurity the analogue is telemetry. Detection and validation depend on stable observation channels.

Two requirements follow:

- Sensors must expose enough internal state for verification, including logs and flow summaries.
- Loss of visibility is itself a signal. Missing logs, broken sensors, or sudden silence can be treated as a danger signal and correlated with other evidence.

## Limits of the analogy

The paper explicitly cautions against direct one-to-one mappings. Several immune mechanisms have no safe or meaningful cybersecurity equivalent:

- Coexistence with pathogens does not apply to production environments. Malware analysis happens in segregated sandboxes.
- Regulated cell death has no network-level equivalent. Process termination exists, but it does not provide the same intrinsic signaling semantics.
- Biology can sacrifice cells. Cybersecurity cannot routinely sacrifice hosts or services. Multi-signal activation and proportional responses are therefore more important than in biology.

The model should be used to structure coordination, gating, and regulation. It should not be used to label a detector as a "T cell" and consider the job done.

## Summary

Slips adopts an immunology-inspired model with the following properties:

- Two-layer defense with distinct latency and precision targets.
- Two signal families: technique-linked signals and danger-linked signals.
- Multi-signal activation for high-impact actions.
- A detector lifecycle with generation, evaluation, refinement, memory, and retirement.
- Graded response with explicit exceptions and explicit resolution.
- Distributed coordination by sharing signals and episode context.

This document describes the model. Concrete implementation details belong in `immune_architecture.md`.
