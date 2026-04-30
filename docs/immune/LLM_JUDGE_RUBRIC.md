# LLM-as-Judge Rubric for Slips IDS Risk Evaluation

## Overview

The evaluation system uses an LLM judge to assess AI-generated analyses of network security incidents from Slips IDS. Each incident is evaluated **twice** — once for cause analysis and once for risk assessment — using separate rubrics. Model outputs are presented to the judge in **randomized order** (labeled A, B, C…) to prevent position bias, with model identities revealed only after scoring.

The final ranking per incident is derived from the **sum of cause + risk total scores** (max 60 points combined).

This rubric applies to the risk assessment pipeline. The summarization pipeline uses a single 1–10 quality score evaluated holistically.

---

## Cause Analysis Rubric

Evaluates how well the model explains *why* the incident occurred.

Each dimension is scored **1–10**. Maximum total: **30 points**.

### Evidence Grounding (1–10)
Does the analysis cite specific events from the DAG (IPs, ports, counts, timestamps)?

| Score | Meaning |
|-------|---------|
| 1–3 | Pure generalities, no specific data referenced |
| 4–6 | Some specifics but incomplete or cherry-picked |
| 7–9 | Systematically references key evidence (scan targets, blacklisted IPs, event counts) |
| 10 | Covers all significant evidence with precise detail |

### Cause Specificity (1–10)
Does the analysis name the specific attack behavior or stay vague?

| Score | Meaning |
|-------|---------|
| 1–3 | "Possible malicious activity" — could apply to any incident |
| 4–6 | Names the attack class but not the specific behavior |
| 7–9 | Identifies specific TTP (e.g. horizontal scan pattern, C2 callback behavior) |
| 10 | Precise TTP with supporting evidence chain |

### Alternative Hypotheses (1–10)
Does the analysis meaningfully consider legitimate or misconfiguration causes?

| Score | Meaning |
|-------|---------|
| 1–3 | Ignores or dismisses alternatives without reasoning |
| 4–6 | Mentions alternatives but without supporting logic |
| 7–9 | Evaluates alternatives against the evidence |
| 10 | Well-reasoned evaluation of all plausible hypotheses |

---

## Risk Assessment Rubric

Evaluates how well the model characterizes *how dangerous* the incident is and what to do about it.

Each dimension is scored **1–10**. Maximum total: **30 points**.

### Risk Calibration (1–10)
Is the risk level proportionate to the actual evidence weight?

| Score | Meaning |
|-------|---------|
| 1–3 | Flat assessment ignoring evidence distribution (e.g. always "High") |
| 4–6 | Correct level but reasoning not tied to evidence |
| 7–9 | Risk level explicitly derived from evidence severity and volume |
| 10 | Nuanced calibration distinguishing between event types and their relative weight |

### Actionability (1–10)
Are recommended actions concrete and scoped to this incident?

| Score | Meaning |
|-------|---------|
| 1–3 | Generic boilerplate ("investigate the IP", "update firewall rules") |
| 4–6 | Incident-specific but vague or unprioritized |
| 7–9 | Concrete actions with priority order tied to specific findings |
| 10 | Scoped response plan with clear sequencing and ownership |

### Business Impact Relevance (1–10)
Is the impact assessment realistic and specific?

| Score | Meaning |
|-------|---------|
| 1–3 | Generic ("data breach risk") — could apply to any incident |
| 4–6 | Relevant but not tied to the specific evidence |
| 7–9 | Impact explicitly derived from the observed behavior |
| 10 | Precise impact with scope and affected assets identified |

---

## Scoring & Ranking

- Each model receives a **cause total** (max 30) and a **risk total** (max 30)
- The **combined score** (cause + risk, max 60) determines the final per-incident ranking
- Rankings are 1 (best) through N (worst) across all evaluated models
- **Win rate** = fraction of incidents where a model ranks 1st

---

## Anti-bias Measures

- Model outputs are presented to the judge in **random order** per incident, relabeled A/B/C/D
- The same randomized order is used for both the cause and risk judge calls within an incident
- The judge is instructed to respond with structured JSON only, preventing narrative drift
- Temperature is set to **0.3** for consistency across calls
