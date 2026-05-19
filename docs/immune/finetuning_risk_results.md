### Risk Fine-Tuned Model: Evaluation Results

**Summary:** The Qwen2.5-1.5B model fine-tuned for Slips cause analysis and risk assessment ranks 2nd overall with avg position 1.73 and 37.3% win rate — nearly tied with GPT-4o (1.70) and ahead of GPT-4o-mini (2.11). The model beats GPT-4o on cause analysis score (15.58 vs 15.33). Primary weakness is risk score calibration (10.27 vs cause score 15.58), reflecting a task imbalance in the training data.

**Model:** [stratosphere/qwen2.5-1.5b-slips-immune-risk](https://huggingface.co/stratosphere/qwen2.5-1.5b-slips-immune-risk)  
**Judge:** qwen3.5 | **Incidents evaluated:** 67 | **Date:** 2026-04-22

---

### Index
- [Overall Rankings](#overall-rankings)
- [Performance by Category](#performance-by-category)
- [Performance by Complexity](#performance-by-complexity)
- [Key Findings](#key-findings)
- [Known Limitations](#known-limitations)

---

### Overall Rankings
| Rank | Model | Avg Position | Avg Cause Score | Avg Risk Score | Win Rate | Wins |
|------|-------|--------------|-----------------|----------------|----------|------|
| 1 | GPT-4o | 1.70 | 15.33 | 11.99 | 40.3% | 27 |
| 2 | **Finetuned 1.5B** | **1.73** | **15.58** | **10.27** | **37.3%** | **25** |
| 3 | GPT-4o-mini | 2.11 | 15.31 | 11.63 | 19.4% | 13 |
| 4 | Qwen2.5 1.5B (baseline) | 3.48 | 9.15 | 8.79 | 3.0% | 2 |
| 5 | Qwen2.5 3B (baseline) | 3.53 | 7.40 | 9.61 | 0.0% | 0 |

Scores are out of 30 for cause and 30 for risk (see [LLM-as-Judge Rubric](LLM_JUDGE_RUBRIC.md)). Rankings are determined by the combined cause + risk total (max 60).

The finetuned 1.5B model is essentially tied with GPT-4o on average position (1.73 vs 1.70) and **outscores GPT-4o on cause analysis** (15.58 vs 15.33). Its 37.3% win rate is nearly double GPT-4o-mini's 19.4% and far above both untuned baselines (3.0% and 0.0%).

---

### Performance by Category
| Category | Count | Cause Score | Risk Score | Win Rate |
|----------|-------|-------------|------------|----------|
| Malware | 47 | 15.52 | 10.08 | 51.1% |
| Normal | 5 | 16.40 | 12.60 | 20.0% |

Malware incidents — the dominant category — show strong performance with >50% win rate. The Normal category result (5 incidents) is not statistically reliable.

---

### Performance by Complexity
| Complexity | Events | Cause Score | Risk Score | Win Rate |
|------------|--------|-------------|------------|----------|
| Simple | < 500 (33 incidents) | 15.70 | 9.32 | 54.5% |
| Medium | 500–1999 (8 incidents) | 19.38 | 12.62 | 50.0% |
| Complex | ≥ 2000 (11 incidents) | 13.20 | 11.80 | 27.3% |

Simple and medium incidents are handled competitively, with win rates above 50%. Complex incidents (≥ 2000 events) are the weak tier, consistent with large DAGs approaching the 4096-token input budget.

---

### Key Findings

1. **Competitive with GPT-4o.** The finetuned 1.5B model nearly matches GPT-4o on overall ranking (avg position 1.73 vs 1.70) and actually beats it on cause analysis score (15.58 vs 15.33). This demonstrates that task-specific fine-tuning can bridge the gap between a 1.5B local model and a large frontier model.

2. **Strong improvement over baselines.** Win rate improves from 0.0% (Qwen2.5 3B baseline) to 37.3%. Cause score improves by +8.18 over the 3B baseline; risk score improves by +0.66. The asymmetry indicates the model learned cause analysis more effectively than risk calibration.

3. **Best on simple and medium incidents.** Win rates of 54.5% (simple) and 50.0% (medium) are well above baseline. These two tiers cover the majority of real Slips incidents, so this is operationally the most important result.

4. **Single adapter, dual task.** Both cause analysis and risk assessment are handled by one LoRA adapter trained on an interleaved combined dataset. This design choice avoids model management overhead — one quantized GGUF file serves both task types at inference time.

---

### Known Limitations
- **Risk scores lag cause scores:** cause avg 15.58 vs risk avg 10.27 — the model is stronger at identifying causes than calibrating risk levels. This reflects task imbalance in the training data (cause examples were higher quality / more consistent). Mitigation: upsample risk training examples 2× in the next training run.
- **Context length ceiling:** incidents with large DAGs exceed the 4096-token input budget. Performance drops on the largest inputs (≥ 2000 events). Mitigation: smarter DAG pre-summarization before the LLM step, or training at higher sequence length.
- **Small eval set for Normal traffic:** 5 Normal incidents is too few for statistically reliable conclusions. The 20.0% Normal win rate should not be compared directly to the 51.1% Malware win rate.

---

For evaluation methodology, see [Fine-Tuning Evaluation Methodology](finetuning_evaluation.md).  
For training details, see [Risk Assessment Training Procedure](finetuning_risk_procedure.md).  
For quantization impact and deployment options, see [Quantization and Deployment](finetuning_quantization.md).
