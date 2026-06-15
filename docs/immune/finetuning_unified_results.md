### Unified Fine-Tuned Model: Evaluation Results

**Summary:** The Qwen2.5-1.5B model fine-tuned for all three Slips analysis tasks (summarization, cause analysis, risk assessment) in a single adapter achieves competitive performance on both tasks: 17.0% win rate on summarization (47 incidents) and 23.9% win rate on risk assessment (67 incidents). Performance is close to — but slightly below — the dedicated standalone models, a reasonable cost for operational simplicity (one GGUF file, three tasks). Quantized GGUF variants match or exceed the fp16 baseline on both tasks.

**Model:** [stratosphere/qwen2.5-1.5b-slips-immune-unified](https://huggingface.co/stratosphere/qwen2.5-1.5b-slips-immune-unified)  
**Judge (summary):** gpt-oss-120b | **Judge (risk):** qwen3.5 | **Incidents evaluated:** 47 (summary) + 67 (risk) | **Date:** 2026-06-09

---

### Index
- [Summary Task Results](#summary-task-results)
- [Risk Task Results](#risk-task-results)
- [Comparison vs Standalone Models](#comparison-vs-standalone-models)
- [Key Findings](#key-findings)
- [Known Limitations](#known-limitations)

---

### Summary Task Results

Evaluated on the same 47 held-out incidents used for the standalone summarization model. Judge: `gpt-oss-120b`.

| Rank | Model | Avg Score /10 | Win Rate |
|------|-------|---------------|----------|
| 1 | GPT-4o-mini | 6.89 | 42.6% |
| 2 | GPT-4o | 5.87 | 29.8% |
| 3 | Qwen2.5 3B | 4.57 | 8.5% |
| 4 | **Unified 1.5B (fp16)** | **5.20** | **17.0%** |
| 5 | Qwen2.5 1.5B (baseline) | 3.36 | 0.0% |

> Note: average score and win rate can diverge because win rate measures first-place finishes only, while average score reflects overall quality. The unified model's 5.20 avg score places it between GPT-4o and Qwen2.5 3B despite a lower win rate than the 3B model.

---

### Risk Task Results

Evaluated on the same 67 held-out incidents used for the standalone risk model. Judge: `qwen3.5`. Scores out of 30 for cause and 30 for risk.

| Rank | Model | Avg Cause /30 | Avg Risk /30 | Win Rate |
|------|-------|---------------|--------------|----------|
| 1 | GPT-4o | 15.33 | 11.99 | 40.3% |
| 2 | GPT-4o-mini | 15.31 | 11.63 | 19.4% |
| 3 | **Unified 1.5B (fp16)** | **18.30** | **12.36** | **23.9%** |
| 4 | Qwen2.5 1.5B (baseline) | 9.15 | 8.79 | 3.0% |
| 5 | Qwen2.5 3B (baseline) | 7.40 | 9.61 | 0.0% |

The unified model achieves a strong cause analysis score (18.30) — above GPT-4o (15.33) — while its risk calibration (12.36) is comparable to GPT-4o-mini (11.63).

---

### Comparison vs Standalone Models

The key operational question: how much does the unified adapter cost vs. a dedicated single-task model?

| Task | Standalone Model | Win Rate | Unified Model | Win Rate | Delta |
|------|-----------------|----------|---------------|----------|-------|
| Summarization | stratosphere/qwen2.5-1.5b-slips-immune | 19.1% | stratosphere/qwen2.5-1.5b-slips-immune-unified | 17.0% | −2.1pp |
| Risk/Cause | stratosphere/qwen2.5-1.5b-slips-immune-risk | 37.3% | stratosphere/qwen2.5-1.5b-slips-immune-unified | 23.9% | −13.4pp |

The summarization quality gap is small (−2.1pp win rate). The risk quality gap is larger (−13.4pp win rate), though the unified model still strongly outperforms both untuned baselines (0.0% and 3.0%).

The risk gap is expected: the standalone risk model was trained exclusively on cause+risk data with r=64, whereas the unified model's adapter capacity (r=128) is shared across three task objectives. The unified model compensates with higher rank but cannot fully match a model optimized for one task.

---

### Key Findings

1. **One adapter, three tasks.** A single LoRA adapter (r=128, RSLoRA) successfully learns all three task formats without catastrophic interference. The model produces structurally correct outputs for all three prompt types without any task-switching mechanism.

2. **Summarization quality nearly preserved.** The 2.1pp win rate drop vs. the standalone summarization model (17.0% vs. 19.1%) is within measurement noise for a 47-incident eval set. For deployments where model management overhead is a concern, the unified model is a practical substitute.

3. **Risk quality gap is real but acceptable.** The 13.4pp win rate gap vs. the standalone risk model reflects the harder multi-task objective. The unified model still dominates both untuned baselines by a wide margin and produces cause analysis scores above GPT-4o.

4. **Quantization does not hurt — it slightly helps.** Unlike the standalone risk model (where fp16 > all quantized variants), the unified model's quantized GGUF variants match or exceed the fp16 baseline on both tasks. This is because the fp16 baseline uses BnB NF4 4-bit quantization at inference (not true fp16 — the evaluation GPU lacked sufficient VRAM for the full model), so the comparison is NF4 vs. GGUF rather than full-precision vs. GGUF. See [Quantization and Deployment](finetuning_quantization.md) for the full quantization evaluation.

5. **q4_k_m is the recommended deployment variant.** At 986 MB, it matches q5_k_m and q8_0 on risk win rate (26.9% each) and is the smallest variant. For RPi5 deployment, q4_k_m is the best size-to-quality trade-off.

---

### Known Limitations

- **Risk quality gap vs. standalone:** if cause+risk analysis quality is the primary concern and operational simplicity is not, the dedicated [stratosphere/qwen2.5-1.5b-slips-immune-risk](https://huggingface.co/stratosphere/qwen2.5-1.5b-slips-immune-risk) model is the stronger choice.
- **Context length ceiling:** incidents with large DAGs (≥ 2000 events) approach the 4096-token input budget. Performance degrades on the largest inputs, consistent with both standalone models. Mitigation: smarter DAG pre-summarization before the LLM step.
- **Small eval set for Normal traffic:** the eval sets are dominated by malware incidents. Normal traffic results are not statistically reliable for either task.

---

For evaluation methodology, see [Fine-Tuning Evaluation Methodology](finetuning_evaluation.md).  
For training details, see [Unified Fine-Tuning: Dataset and Training Procedure](finetuning_unified_procedure.md).  
For quantization impact and deployment options, see [Quantization and Deployment](finetuning_quantization.md).
