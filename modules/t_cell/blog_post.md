# T Cells in [Slips](https://github.com/stratosphereips/StratosphereLinuxIPS): Adaptive Response on Top of Innate Evidence

The original
[Slips](https://github.com/stratosphereips/StratosphereLinuxIPS) pipeline is
good at turning traffic into evidence. It can detect scans, suspicious ports,
DNS anomalies, HTTP oddities, TLS issues, and many other behaviors, and it can
do that across large volumes of traffic. But producing evidence is not the same
thing as having an immune response.

If every suspicious event is treated in isolation, the system misses some of
the most important immune ideas:

- recognition should be separated from activation
- danger should matter, not just pattern match
- tolerance should be explicit
- memory should be explicit
- containment should happen only after enough evidence and context accumulate

That is the problem the T Cell module is trying to solve.

[Slips](https://github.com/stratosphereips/StratosphereLinuxIPS) is now moving
from a pure detection pipeline toward a system that implements immunology
concepts directly. The existing detector structure remains the innate layer,
and the adaptive layer is added on top.

[Slips](https://github.com/stratosphereips/StratosphereLinuxIPS) now has an immune-style responder that sits on top of the existing
evidence pipeline and decides when recognition should stay tolerant, when it
should activate, when it should contain, and when it should store memory.

That responder is:

- `modules/t_cell/t_cell.py`

It is not a replacement for the old detectors. It is an adaptive layer that
uses the old detectors as its innate immune system and uses the accepted regex
repertoire from `RegexGenerator` as its recognition library.

That connection matters because the adaptive side in [Slips](https://github.com/stratosphereips/StratosphereLinuxIPS) is now split into
two cooperating pieces:

- `RegexGenerator` continually generates new candidate receptors through the
  shared `LLM` module and keeps only the regexes that survive local selection
- `T Cell` consumes those accepted receptors against live `PAMP` evidence and
  combines them with `DAMP` danger context to decide what to do

![T Cell HTML report overview](../../docs/images/t_cell/t_cell_report_overview.png)

## Innate and Adaptive Immunity in [Slips](https://github.com/stratosphereips/StratosphereLinuxIPS)

The immune split in [Slips](https://github.com/stratosphereips/StratosphereLinuxIPS) is now clear:

- the innate immune system is the existing [Slips](https://github.com/stratosphereips/StratosphereLinuxIPS) detection structure plus the
  central `PAMP` / `DAMP` signal tagging
- the adaptive immune system is the combination of `RegexGenerator` and
  `T Cell`

This is the important architectural idea.

The old [Slips](https://github.com/stratosphereips/StratosphereLinuxIPS) modules still do what they always did:

- inspect network behavior
- detect suspicious conditions
- emit evidence

What changed is that [Slips](https://github.com/stratosphereips/StratosphereLinuxIPS) now centrally tags evidence with an
`evidence_signal`:

- `PAMP`
- `DAMP`

That gives the T Cell module a biologically meaningful input vocabulary.

The adaptive part then adds two capabilities:

1. `RegexGenerator` creates a validated receptor library.
2. `T Cell` uses that library plus live danger context to decide what to do.

## What the T Cell Module Actually Does

The T Cell module subscribes to the shared `evidence_added` channel.

For each relevant evidence, it stores its own observation and then decides
whether a T cell should:

- stay mature
- recognize an antigen
- become tolerant
- activate
- contain
- remember

It tracks one cell per:

- responsible IP
- regex type
- normalized antigen value

That means the unit of response is not "all evidence for a profile." It is a
more precise adaptive unit tied to a responsible source and one structured
antigen candidate.

## Why the Responsible IP Matters

One of the key implementation details is that T Cell does not simply act on
`evidence.profile.ip`.

[Slips](https://github.com/stratosphereips/StratosphereLinuxIPS) evidence has several roles at once:

- `profile.ip`: the related profile bucket
- `attacker`: the responsible entity
- `victim`: the target entity
- `direction`: whether a network entity appeared on the `SRC` or `DST` side

Those are not the same thing.

T Cell derives a responsible IP from the evidence and uses that value for:

- cell ownership
- danger aggregation
- reevaluation
- containment

So when the evidence says one machine was the victim but another was the
attacker, containment targets the responsible source, not just the profile
bucket that happened to hold the evidence.

## The Connection to RegexGenerator

The T Cell module depends directly on the regex repertoire built by
`RegexGenerator`.

When a `PAMP` arrives, T Cell extracts structured antigens such as:

- domains
- URIs
- filenames
- TLS SNI values
- certificate common names

It then checks whether any accepted regex of the same type matches that
antigen.

This is the adaptive recognition step.

Without `RegexGenerator`, T Cell would still see `PAMP` and `DAMP`, but it
would not have a receptor library to consult. With `RegexGenerator`, the T Cell
can treat live evidence as candidate antigens and test them against an accepted
adaptive repertoire.

That is why the two modules belong together conceptually:

- `RegexGenerator` builds the receptors
- `T Cell` uses them in live response

## State 0: Mature

Every cell starts in:

- `0 - mature`

At this point there is no recognition yet.

The module stores the observation and checks whether the evidence can even
produce a usable antigen candidate. If not, the evidence is logged and kept as
observation data, but it does not create a useful recognition event.

## From Mature to Antigen Recognition

Only `PAMP` evidence can start recognition from `0 - mature`.

That is deliberate. `PAMP` is the structured trigger that tells the adaptive
layer there may be something pathogen-like worth recognizing.

T Cell extracts antigen candidates from:

- evidence entities
- linked DNS altflows
- linked HTTP altflows
- linked SSL/TLS altflows

If an accepted regex matches one of those antigens, the cell moves to:

- `1 - antigen-recognized`

If an antigen is present but no accepted regex matches, the cell moves to:

- `2 - anergic`

That is the tolerance path. The system saw a candidate antigen, checked its
adaptive repertoire, and found no reason to escalate.

## Co-Stimulation: Recognition Is Not Enough

A recognized antigen still does not automatically become an active response.

The next question is whether there is enough danger to justify activation.

The module computes co-stimulation from:

- the confidence of the current `PAMP`
- the number of related `PAMP` observations
- the weighted cumulative danger seen for the same responsible IP

That danger term includes both:

- `PAMP`
- `DAMP`

This is exactly where the innate and adaptive layers meet.

The regex match says:

- this pattern looks recognizable

The co-stimulation score says:

- is the surrounding danger level high enough to matter?

If the threshold is crossed, the cell becomes:

- `3 - activated`

If not, the cell can wait for one [Slips](https://github.com/stratosphereips/StratosphereLinuxIPS) time window in an explicit waiting
substatus.

## Why DAMP Matters So Much

`DAMP` evidence does not create a new T cell by itself.

But it is still crucial.

`DAMP` does three important things:

- it is stored as danger context
- it contributes to the cumulative danger term in co-stimulation
- it re-triggers reevaluation of cells that are already waiting

That means the innate danger layer is not passive background data. It actively
shapes how the adaptive layer behaves.

Without `DAMP`, T Cell would only know that something matched.

With `DAMP`, T Cell can tell whether the surrounding situation is intensifying,
stable, or cooling down.

## Context: Activated Is Still Not the End

Once a cell reaches:

- `3 - activated`

it still needs to decide what kind of response makes sense.

The context stage looks at:

- novelty
- related evidence volume
- recent pressure versus previous pressure
- weighted `PAMP` + `DAMP` danger

The purpose of this stage is to distinguish between two very different
situations:

- a new, intense threat that should be stopped quickly
- a familiar threat pattern that is still visible but already cooling down

## Effector vs Memory

If the context signals say the threat is new and intense enough, the cell moves
to:

- `4 - effector`

At that point T Cell reuses the existing [Slips](https://github.com/stratosphereips/StratosphereLinuxIPS) containment path and can trigger
blocking behavior such as ARP-poisoning-based isolation through the normal
blocking flow.

If the context signals say the threat is familiar and decreasing, the cell
moves to:

- `5 - memory`

That path stores:

- the matched regex
- the matched value
- the context snapshot

in the T Cell SQLite store for later reuse.

This is what makes the module more than a simple thresholded blocker. It is
explicitly modeling both response and retention.

## Waiting Is a First-Class Runtime Condition

Two states can wait:

- `1 - antigen-recognized`
- `3 - activated`

Those are not extra numbered states. They are explicit waiting substates
recorded on the cell context:

- waiting for co-stimulation
- waiting for context

That makes the runtime easier to interpret because a cell can be:

- recognized but still not dangerous enough
- activated but still not ready for effector or memory

And both of those waiting conditions are reevaluated on later `PAMP` or later
`DAMP` arrivals for the same responsible IP.

## Why This Is More Than a Fancy Alert Filter

The T Cell module is not just filtering alerts after the fact.

It adds an actual stateful decision layer:

- recognition
- tolerance
- co-stimulation
- activation
- context
- effector response
- memory

That matters because it lets [Slips](https://github.com/stratosphereips/StratosphereLinuxIPS) reason about events across time instead of
treating each evidence row as a fully independent trigger.

The module is effectively asking:

- does this look recognizable?
- is it dangerous enough?
- is it urgent enough?
- or is it something we should remember instead?

That is a very different model from direct one-shot escalation.

## Why the T Cell Module Needs the Regex Module

The T Cell module can only be adaptive because it has something adaptive to
consult.

That comes from `RegexGenerator`.

If the regex module did not exist, T Cell would still have:

- `PAMP`
- `DAMP`
- danger aggregation
- thresholds

But it would not have a selected symbolic recognition library.

It would know danger, but not adaptive antigen recognition.

So the full adaptive design requires both modules:

- `RegexGenerator` creates the detector repertoire through pseudo-generation and
  negative selection
- `T Cell` uses that repertoire inside a state machine that decides whether to
  tolerate, activate, contain, or remember

## Why This Is an Immune System and Not Just a Metaphor

The mapping is close enough to be useful in engineering terms:

- old [Slips](https://github.com/stratosphereips/StratosphereLinuxIPS) detectors -> innate sensing
- central `PAMP` / `DAMP` tagging -> innate danger language
- `RegexGenerator` -> adaptive receptor repertoire generation
- benign-corpus rejection -> negative selection
- `T Cell` state machine -> activation, tolerance, context, effector, memory

The value of the metaphor is not decoration. It gives [Slips](https://github.com/stratosphereips/StratosphereLinuxIPS) a concrete design
for how to:

- add adaptive recognition without replacing the old system
- separate recognition from activation
- separate activation from action
- keep explicit tolerance and explicit memory

## What You Can Inspect

The module stores its own artifacts per run:

- `t_cell.log`
- `t_cell.sqlite`
- optional `t_cell_trace.jsonl`
- `t_cell_report.html`

The report gives a static explanation of what happened:

- how much of the run was `PAMP` versus `DAMP`
- which antigens were extracted
- which regexes matched
- which cells moved through the state machine
- which cells are waiting now
- which cells became memory or effector
- why thresholds were crossed when decision tracing was enabled

So the module is not only stateful. It is also inspectable.

## In Short

The T Cell module is the adaptive response engine in [Slips](https://github.com/stratosphereips/StratosphereLinuxIPS).

It takes:

- innate evidence from the old detector structure
- `PAMP` / `DAMP` tags from the central evidence pipeline
- accepted regex receptors from `RegexGenerator`

and turns them into a stateful decision process that can:

- recognize
- tolerate
- activate
- contain
- and remember

That is what makes the current [Slips](https://github.com/stratosphereips/StratosphereLinuxIPS) immune architecture coherent:

- innate sensing from the legacy evidence layer
- adaptive receptor generation from `RegexGenerator`
- adaptive live response from `T Cell`
