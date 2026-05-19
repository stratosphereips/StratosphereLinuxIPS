### Risk Assessment & Cause Analysis Fine-Tuning: Dataset and Training Procedure

**Summary:** The risk model is trained on a quality-filtered subset of the Slips cause & risk dataset, using the highest-scoring model response per task per incident as the training target. A single LoRA adapter handles both cause analysis and risk assessment, trained on an interleaved combined dataset. This document covers the risk-specific dataset preparation and training configuration.

---

### Index
- [Dataset](#dataset)
- [Step 1 — Quality Filtering](#step-1--quality-filtering)
- [Step 2 — Ground Truth Selection](#step-2--ground-truth-selection)
- [Training](#training)
- [Published Model](#published-model)

---

### Dataset
**Source:** [risk_dataset_v2.json](https://github.com/stratosphereips/Slips-tools/raw/refs/heads/main/alert_summary/datasets/risk_dataset_v2.json.gz)  
826 security incidents from Slips, each with four LLM-generated cause analyses and risk assessments (GPT-4o, GPT-4o-mini, Qwen2.5 3B, Qwen2.5 1.5B) and associated LLM-as-judge quality scores.

For how this dataset was generated, see [Risk Analysis Dataset Report](DATASET_RISK_REPORT.md).

---

### Step 1 — Quality Filtering
[`filter_dataset_risk.py`](https://github.com/stratosphereips/Slips-tools/blob/main/unsloth-scripts/filter_dataset_risk.py) applies five filters per incident:

- **Cause score threshold:** reject if best model cause score < 14 (bottom quality quartile)
- **Risk score threshold:** reject if best model risk score < 10
- **Cause token length:** reject if best cause response is < 50 or > 600 tokens
- **Risk token length:** reject if best risk response is < 30 or > 300 tokens
- **Risk level keyword:** reject if risk assessment does not contain a valid level keyword (Critical / High / Medium / Low)

Surviving incidents are split 90/10 into train and eval sets (`random_state=42`).

```bash
cd unsloth-scripts/
python3 filter_dataset_risk.py
# Outputs: risk_filtered_train.json, risk_filtered_eval.json
```

---

### Step 2 — Ground Truth Selection
[`select_best_responses_risk.py`](https://github.com/stratosphereips/Slips-tools/blob/main/unsloth-scripts/select_best_responses_risk.py) selects the highest-scoring model response per task per incident and formats records as two-turn SFT conversations:

- `user` — single message containing the instructions (security analyst persona, task description, output format rules) and the DAG analysis text
- `assistant` — best-scoring cause analysis or risk assessment (ground truth)

No system prompt is used. Cause and risk records are interleaved into a single combined dataset so the model sees both task types throughout training. This single combined dataset trains one adapter that handles both tasks.

DAG inputs exceeding the token budget are truncated at 3500 tokens with an explicit truncation marker.

```bash
python3 select_best_responses_risk.py
# Outputs: risk_combined_train_dataset.json (1328 records), risk_combined_eval_dataset.json (148 records)
```

The final combined dataset contains 1328 train / 148 eval records (90/10 split from 826 source incidents × 2 tasks, after filtering).

---

### Training
Training follows the general procedure in [Fine-Tuning Approach](finetuning_procedure.md). Risk-specific config values:

| Parameter | Value |
|---|---|
| Max sequence length | 4096 |
| LoRA rank (`r`) | 64 |
| LoRA alpha | 64 |
| LoRA dropout | 0.0 |
| RSLoRA | enabled (required at r=64) |
| LoRA targets | q_proj, k_proj, v_proj, o_proj, gate_proj, up_proj, down_proj |
| Epochs | 3 |
| Learning rate | 2e-5 |
| LR scheduler | cosine |
| Warmup steps | 20 |
| Weight decay | 0.01 |
| Batch size (effective) | 16 (1 × grad accum 16) |
| Optimizer | adamw_8bit |
| Precision | BF16 |
| Quantization (training) | 4bit (QLoRA) |
| Hardware | A100 80GB MiG 20GB slice (e-infra.cz cloud) |

```bash
python3 train_qwen.py --config config_risk_4096_20gb.yaml
# Reads config, outputs merged 16-bit weights + GGUF (q4_k_m, q5_k_m, q8_0)
```

A key difference from the summarization model: the higher LoRA rank (r=64 vs r=16) with RSLoRA enabled is required to handle the dual-task objective. The combined interleaved dataset ensures the adapter learns both cause analysis and risk assessment without task interference.

---

### Published Model
The trained model is published on HuggingFace:

> **[stratosphere/qwen2.5-1.5b-slips-immune-risk](https://huggingface.co/stratosphere/qwen2.5-1.5b-slips-immune-risk)**

For evaluation results, see [Risk Fine-Tuned Model: Evaluation Results](finetuning_risk_results.md).  
For GGUF conversion and Ollama deployment, see [Quantization and Deployment](finetuning_quantization.md).
