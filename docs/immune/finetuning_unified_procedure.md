### Unified Fine-Tuning: Dataset and Training Procedure

**Summary:** The unified model trains a single LoRA adapter to handle all three analysis tasks — incident summarization (Task S), cause analysis (Task A), and risk assessment (Task B) — from one GGUF file. It uses a purpose-built 5-script dataset pipeline that intersects the summarization and risk source datasets and augments with risk-only incidents to counteract task dilution. The production model trains on 2195 SFT records with lora_r=128 + RSLoRA.

---

### Index
- [Motivation](#motivation)
- [Dataset](#dataset)
- [Step 1 — Merge Summary Judge Results](#step-1--merge-summary-judge-results)
- [Step 2 — Build Unified Dataset](#step-2--build-unified-dataset)
- [Step 3 — Filter Dataset](#step-3--filter-dataset)
- [Step 4 — Select Best Responses and Augment](#step-4--select-best-responses-and-augment)
- [Training](#training)
- [Published Model](#published-model)

---

### Motivation

Running two separate models on the Raspberry Pi 5 — one for summarization, one for cause+risk — requires loading and unloading GGUF files between tasks, adding memory and latency overhead. A unified adapter handles all three tasks from a single model file, eliminating model-switching at deployment time.

The trade-off is a harder training objective: one adapter must learn three distinct output formats and reasoning patterns simultaneously. This requires a higher LoRA rank than either standalone model, and a dataset that gives each task type adequate representation throughout training.

---

### Dataset

**Source datasets:**

| Dataset | Records | Description |
|---------|---------|-------------|
| `summarization_dataset_v4.json` | 961 | Summary LLM responses (GPT-4o, GPT-4o-mini, Qwen2.5 1.5B, Qwen2.5 3B) |
| `risk_dataset_v2.json` | 826 | Cause+risk LLM responses + dag_analysis |
| `summarization_results_merged.json` | 802 | Summary judge scores (gpt-oss-120b) |
| `risk_dataset_v2_results_qwen35.json` | 826 | Cause+risk judge scores (Qwen3.5, subscored) |

The unified pipeline requires every incident to have both summary and risk judge scores — a stricter requirement than either standalone pipeline. Only the 802 incidents scored on both tasks enter the pipeline. The final training set contains **2195 SFT records** across all three task types.

The final SFT dataset is published on HuggingFace: **[stratosphere/immune-unified-sft-dataset](https://huggingface.co/datasets/stratosphere/immune-unified-sft-dataset)**

For how the source datasets were generated, see [Summarization Dataset Report](DATASET_REPORT.md) and [Risk Analysis Dataset Report](DATASET_RISK_REPORT.md).

---

### Step 1 — Merge Summary Judge Results

[`merge_summary_results.py`](https://github.com/stratosphereips/Slips-tools/blob/main/alert_summary/merge_summary_results.py) merges judge results from two evaluation runs into a single file:

- `summarization_dataset_v3_results_oss.json` (532 incidents, gpt-oss-120b via e-infra.cz)
- `summarization_v4_new_results_oss.json` (270 new v4 incidents, gpt-oss-120b via NVIDIA NIM)

**Output:** `summarization_results_merged.json` — 802 incidents with summary judge scores.

---

### Step 2 — Build Unified Dataset

[`build_unified_dataset.py`](https://github.com/stratosphereips/Slips-tools/blob/main/alert_summary/build_unified_dataset.py) joins all four source datasets on `incident_id`, keeping only the 802 incidents scored on both tasks:

- Identity fields + timeline from `summarization_dataset_v4.json`
- `dag_analysis` from `risk_dataset_v2.json` (full coverage for all 802)
- Summary LLM responses (4 models) from `summarization_dataset_v4.json`
- Cause+risk LLM responses (4 models) from `risk_dataset_v2.json`
- Summary judge scores from `summarization_results_merged.json`
- Cause+risk subscored judge scores from `risk_dataset_v2_results_qwen35.json`

**Output:** `datasets/unified_dataset.json` — 802 incidents.

---

### Step 3 — Filter Dataset

[`filter_dataset_unified.py`](https://github.com/stratosphereips/Slips-tools/blob/main/alert_summary/filter_dataset_unified.py) applies quality thresholds from both standalone pipelines simultaneously — an incident must pass all filters to be retained:

| Filter | Threshold |
|--------|-----------|
| Best summary score | ≥ 4 / 10 |
| Best cause total | ≥ 14 / 30 |
| Best risk total | ≥ 10 / 30 |
| Summary response token length | 50–400 tokens |
| Cause response token length | 50–600 tokens |
| Risk response token length | 30–300 tokens |
| Risk level keyword | Critical / High / Medium / Low |

**Result:** 750 / 802 incidents passed (93.5%). Split 90/10 (seed=42): **675 train / 75 eval**.

The intersection requirement excludes incidents that passed the standalone risk quality filter but have no summary judge score. To recover those risk training examples, Step 4 appends them separately.

---

### Step 4 — Select Best Responses and Augment

[`select_best_responses_unified.py`](https://github.com/stratosphereips/Slips-tools/blob/main/alert_summary/select_best_responses_unified.py) selects the highest-scoring model response per task per incident and builds SFT conversation records:

- **Task S**: best summary score (1–10) → `[system, user(dag), assistant(summary)]`
- **Task A**: best cause total (subscored) → `[user(cause_prompt+dag), assistant(cause_analysis)]`
- **Task B**: same winner as Task A → `[user(risk_prompt+dag), assistant(risk_assessment)]`

DAG inputs are truncated at 3500 tokens at clean line boundaries with an explicit truncation marker. Records are interleaved S→A→B per incident so the adapter sees all three task types continuously throughout training.

**Intermediate output:** `unified_train_dataset.json` — 2025 train records (675 × 3 tasks).

The three task types use distinct prompt formats:

| Task | Prompt focus | Output structure |
|---|---|---|
| **Task S** (Summarization) | Human-readable incident summary | Summary + Key Events + Threat Assessment |
| **Task A** (Cause Analysis) | Structured root cause identification | Possible Causes × 3 categories + Conclusion |
| **Task B** (Risk Assessment) | Calibrated risk evaluation | Risk Level + Justification + Business Impact + Likelihood + Priority |

**Augmentation with risk-only incidents:** The intersection requirement keeps only incidents with both summary and risk scores, which naturally shrinks the risk-task pool: the unified pipeline produces 675 cause+risk training records, compared to 1328 in the standalone risk pipeline. This halving of risk-specific signal causes task dilution — the model learns cause and risk analysis from fewer examples relative to the standalone model.

To recover this signal without modifying the unified pipeline, [`augment_unified_with_risk.py`](https://github.com/stratosphereips/Slips-tools/blob/main/unsloth-scripts/augment_unified_with_risk.py) appends cause+risk SFT records from **risk-only incidents** — incidents present in `risk_filtered_train.json` (standalone risk train split) that were excluded from the unified pipeline because they lacked summary judge scores. Of the 151 incidents in `risk_dataset_v2` but not in the unified pool, 85 passed `filter_dataset_risk.py` quality filters and are appended.

The augmentation uses the same prompt templates and DAG truncation (3500 tokens) as `select_best_responses_unified.py`. Each incident contributes two records (cause + risk), interleaved before appending.

| Source | Incidents | Records |
|--------|-----------|---------|
| Unified filtered train (S+A+B) | 675 | 2025 |
| Risk-only extras (A+B only) | 85 | 170 |
| **Augmented total** | **760** | **2195** |

**Final output:** `unified_train_dataset_augmented.json` — **2195 train records** (675 summary + 760 cause + 760 risk).

```bash
cd alert_summary/
python3 merge_summary_results.py
python3 build_unified_dataset.py
python3 filter_dataset_unified.py
python3 select_best_responses_unified.py

cd ../unsloth-scripts/
python3 augment_unified_with_risk.py
# Output: unified_train_dataset_augmented.json (2195 records)
```

---

### Training

Training follows the general procedure in [Fine-Tuning Approach](finetuning_procedure.md). Config: [`config_unified_4096_20gb_v2.yaml`](https://github.com/stratosphereips/Slips-tools/blob/main/unsloth-scripts/config_unified_4096_20gb_v2.yaml).

| Parameter | Value |
|---|---|
| Max sequence length | 4096 |
| LoRA rank (`r`) | 128 |
| LoRA alpha | 128 |
| LoRA dropout | 0.0 |
| RSLoRA | enabled (required at r=128) |
| LoRA targets | q_proj, k_proj, v_proj, o_proj, gate_proj, up_proj, down_proj |
| Epochs | 2 |
| Learning rate | 2e-5 |
| LR scheduler | cosine |
| Warmup steps | 20 |
| Weight decay | 0.01 |
| Batch size (effective) | 16 (2 × grad accum 8) |
| Optimizer | adamw_8bit |
| Precision | BF16 |
| Quantization (training) | 4bit (QLoRA) |
| Hardware | A100 80GB MiG 20GB slice (e-infra.cz cloud) |

The higher LoRA rank (r=128 vs r=16 for summarization, r=64 for risk) gives the adapter more representational capacity for three competing task objectives. RSLoRA normalizes the adapter contribution at higher ranks to prevent training instability. Two epochs are used to avoid overfitting toward the most frequent task pattern (summary) in the mixed dataset.

```bash
cd unsloth-scripts/
python3 train_qwen.py --config config_unified_4096_20gb_v2.yaml
# Outputs: qwen_unified_finetuned_v2/ (adapter) + qwen_unified_finetuned_v2_merged_16bit/
```

---

### Training History Notes

**v1** used the base `unified_train_dataset.json` (2025 records, lora_r=64, 3 epochs). Evaluation showed that risk and cause analysis performance was significantly below the standalone risk model. The root cause was task dilution: at r=64, the adapter did not have enough capacity to learn all three tasks simultaneously, and the summary task — being the most frequent pattern — dominated training signal at the cost of risk quality.

**v3** was an experiment that doubled all cause+risk records via 2× upsampling (`unified_train_dataset_augmented_2x_risk.json`). It backfired: the model overfit to the repeated pattern, producing a win rate drop of −6.4pp on summary and −13.5pp on risk compared to v2. v2, which reaches the same ~80% cause+risk proportion naturally from dataset sizes, is the better-calibrated training distribution.

---

### Published Model

The trained model is published on HuggingFace:

> **[stratosphere/qwen2.5-1.5b-slips-immune-unified](https://huggingface.co/stratosphere/qwen2.5-1.5b-slips-immune-unified)**

For evaluation results, see [Unified Fine-Tuned Model: Evaluation Results](finetuning_unified_results.md).  
For GGUF conversion and Ollama deployment, see [Quantization and Deployment](finetuning_quantization.md).
