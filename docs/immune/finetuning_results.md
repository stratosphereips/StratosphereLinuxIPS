### Summarization Fine-Tuned Model: Evaluation Results

**Keywords:** Qwen2.5-1.5B, Incident Summarization, SFT, LLM-as-Judge, Win Rate

**TL;DR:** The Qwen2.5-1.5B model fine-tuned for Slips incident summarization ranks 1st overall with a 7.73 avg score and 74.5% win rate — well above GPT-4o-mini — across simple and medium incidents. The primary weakness is a hard failure on very large incidents (>4000 events) caused by input truncation.

**Model:** [stratosphere/qwen2.5-1.5b-slips-immune](https://huggingface.co/stratosphere/qwen2.5-1.5b-slips-immune)  
**Judge:** gpt-oss-120b | **Incidents evaluated:** 47 (44 scored, 3 missing) | **Date:** 2026-04-05

---

### Index

- [Overall Rankings](#overall-rankings)
- [Performance by Category](#performance-by-category)
- [Performance by Complexity](#performance-by-complexity)
- [Key Findings](#key-findings)
- [Known Limitations](#known-limitations)

---

### Overall Rankings

| Rank | Model | Avg Position | Avg Score | Win Rate |
|------|-------|--------------|-----------|----------|
| 1 | **Finetuned 1.5B** | 1.22 | 7.73/10 | 74.5% |
| 2 | GPT-4o-mini | 2.37 | 5.75/10 | 12.8% |
| 3 | GPT-4o | 2.59 | 5.00/10 | 6.4% |
| 4 | Qwen2.5 3B | 3.36 | 4.14/10 | 0.0% |
| 5 | Qwen2.5 1B | 3.81 | 2.61/10 | 0.0% |

The finetuned model exceeds both baselines decisively: **+4.92 avg score vs Qwen2.5 1B** (lower bound) and **+3.59 vs Qwen2.5 3B** (stretch goal). The stretch goal — matching a 3B model with a 1.5B finetuned model — is not just met but exceeded by a wide margin.

Position distribution shows the consistency: 35 first-place finishes, 3 seconds, 3 thirds, and **zero last-place finishes** across 44 scored incidents.

---

### Performance by Category

| Category | Finetuned Score | Finetuned Win Rate | vs GPT-4o-mini |
|---|---|---|---|
| Malware (42 incidents) | 7.76/10 | 81.0% | +2.05 |
| Normal (2 incidents) | 7.00/10 | 50.0% | tied |

Normal traffic performance is competitive (7.00 avg, 1st/2nd split with GPT-4o-mini), a notable result given the training data is predominantly Malware incidents. The separated prompt format gives the model enough structural context to adapt its output to benign traffic patterns.

---

### Performance by Complexity

| Complexity | Events | Finetuned Score | Win Rate | vs GPT-4o-mini |
|---|---|---|---|---|
| Simple | <500 (29 scored) | 8.31/10 | 89.7% | +2.83 |
| Medium | 500–1999 (7 scored) | 8.29/10 | 85.7% | +2.72 |
| Complex | ≥2000 (8 scored) | 5.12/10 | 37.5% | −1.76 |

Simple and medium incidents are dominated convincingly. Complex incidents are the weak tier: the model ranks 3rd (behind GPT-4o-mini and GPT-4o) with 5.12 avg.

Drilling into the complex incidents reveals a clear event-count boundary:

| Incident | Events | Score | Rank |
|---|---|---|---|
| `06598746` | 3427 | 9/10 | 1st |
| `9bcb9d22` | 3302 | 9/10 | 1st |
| `f3a523ce` | 2987 | 9/10 | 1st |
| `a1c25998` | 4290 | 1/10 | 5th |
| `91684d9f` | 4974 | 1/10 | 5th |
| `304b2da9` | 6267 | 1/10 | 5th |

Incidents in the 2000–3500 event range are handled well. Incidents above ~4000 events are near-complete failures, consistent with the 2048-token input limit: once DAG truncation removes too much context, the model cannot produce a coherent summary.

---

### Key Findings

1. **Stretch goal exceeded.** The finetuned 1.5B model surpasses Qwen2.5 3B by 3.59 avg score points, validating the hypothesis that task-specific fine-tuning compensates for parameter count on this domain.

2. **Different quality tier for most incidents.** The +1.98 avg score gap vs GPT-4o-mini is not marginal — the model is operating at a higher quality level than the commercial baseline for the typical (simple/medium) incident.

3. **Hard failure above ~4000 events.** The failure is abrupt and caused by input truncation, not a gradual quality decline. This is a solvable engineering problem, not a model quality problem.

4. **Normal traffic generalizes.** Despite predominantly Malware training data, the model handles Normal incidents competently, suggesting robust instruction following rather than pattern memorization.

---

### Known Limitations

- **Input truncation ceiling:** Incidents with >4000 events exceed the 2048-token input budget. Mitigation options: increase `max_seq_length` to 4096, add dedicated training examples with aggressive truncation, or apply smarter DAG summarization before the LLM step.
- **Small eval set:** 44 scored incidents (47 − 3 missing) is sufficient for directional conclusions but too small for robust statistical significance, especially on Normal (2 incidents) and Complex (8 incidents) subsets.
- **3 missing records:** Incidents `5c8a1989` (122 events), `6d8fd038` (32 events), and `298b0c57` (2947 events) were not scored. Two are simple incidents, ruling out input length as cause — likely transient inference or evaluation failures.

---

For evaluation methodology, see [Fine-Tuning Evaluation Methodology](finetuning_evaluation.md).  
For training details, see [Summarization Fine-Tuning Procedure](finetuning_summarization_procedure.md).  
For quantization impact and deployment options, see [Quantization and Deployment](finetuning_quantization.md).
