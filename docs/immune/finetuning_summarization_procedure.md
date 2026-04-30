### Summarization Fine-Tuning: Dataset and Training Procedure

**Summary:** The summarization model is trained on a quality-filtered subset of the Slips summarization dataset, using the highest-scoring model response per incident as the training target. The same general LoRA+Unsloth pipeline applies; this document covers the summarization-specific dataset preparation and system prompt.

---

### Index
- [Dataset](#dataset)
- [Step 1 — Quality Filtering](#step-1--quality-filtering)
- [Step 2 — Ground Truth Selection](#step-2--ground-truth-selection)
- [Training](#training)
- [Published Model](#published-model)

---

### Dataset
**Source:** [summarization_dataset_v3.json](https://github.com/stratosphereips/Slips-tools/raw/refs/heads/main/alert_summary/datasets/summarization_dataset_v3.json.gz)  
532 security incidents from Slips, each with four LLM-generated summaries (GPT-4o, GPT-4o-mini, Qwen2.5 1B, Qwen2.5 3B) and associated LLM-as-judge quality scores.

For how this dataset was generated, see [Summarization Dataset Report](DATASET_REPORT.md).

---

### Step 1 — Quality Filtering
[`filter_dataset.py`](https://github.com/stratosphereips/Slips-tools/blob/main/unsloth-scripts/filter_dataset.py) applies two filters per incident:

- **Score threshold:** reject if best model score < 4 (bottom quality quartile)
- **Token length:** reject if best response summary is < 50 or > 400 tokens (too short = trivial; too long = likely template failure or prompt echo)

Surviving incidents are split 90/10 into train and eval sets (`random_state=42`).

```bash
cd unsloth-scripts/
python3 filter_dataset.py
# Outputs: filtered_train.json, filtered_eval.json
```

---

### Step 2 — Ground Truth Selection
[`select_best_responses.py`](https://github.com/stratosphereips/Slips-tools/blob/main/unsloth-scripts/select_best_responses.py) selects the highest-scoring model response per incident and formats each record as a two-turn SFT conversation using a **merged prompt format**:

- `user` — a single message containing both the instructions (security analyst persona, task description, output format rules) and the DAG analysis text
- `assistant` — best-scoring summary (ground truth)

No system prompt is used. Instructions and DAG are concatenated into one user message so the model learns to handle both in the same context.

DAG inputs exceeding the token budget are truncated at clean line boundaries with an explicit truncation marker, so the model learns to handle partial inputs gracefully.

```bash
python3 select_best_responses.py
# Outputs: train_dataset.json, eval_dataset.json
```

The user message instructs the model to group identical events, assign severity labels (CRITICAL / HIGH / MEDIUM / LOW / INFO), and produce a fixed structured output format. This format is what the judge and downstream Slips components expect.

---

### Training
Training follows the general procedure in [Fine-Tuning Approach](finetuning_procedure.md). Summarization-specific config values:

| Parameter | Value |
|---|---|
| Max sequence length | 4096 |
| Epochs | 3 |
| Learning rate | 1e-5 |
| LoRA dropout | 0.05 |
| Batch size (effective) | 8 (1 × grad accum 8) |
| Precision | FP16 |
| Quantization (training) | 4bit |
| Hardware | A100 80GB MiG 20GB slice (e-infra.cz cloud) |

```bash
python3 train_qwen.py
# Reads config.yaml, outputs merged 16-bit weights + GGUF (q4_k_m)
```

---

### Published Model
The trained model is published on HuggingFace:

> **[stratosphere/qwen2.5-1.5b-slips-immune](https://huggingface.co/stratosphere/qwen2.5-1.5b-slips-immune)**

For evaluation results, see [Summarization Fine-Tuned Model: Evaluation Results](finetuning_results.md).  
For GGUF conversion and Ollama deployment, see [Quantization and Deployment](finetuning_quantization.md).
