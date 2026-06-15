### Fine-Tuning Evaluation Methodology

**Summary:** Fine-tuned models are evaluated using the same LLM-as-judge framework used for baseline comparison, extended to include the finetuned model as a fifth competitor. The methodology — blind comparative ranking, three metrics, two breakdown dimensions — is identical across tasks.

---

### Index
- [Overview](#overview)
- [Evaluation Pipeline](#evaluation-pipeline)
- [Baselines and Success Criteria](#baselines-and-success-criteria)
- [Metrics](#metrics)
- [Breakdown Dimensions](#breakdown-dimensions)
- [Running the Evaluation](#running-the-evaluation)
- [Task-Specific Results](#task-specific-results)

---

### Overview
After fine-tuning, the model is evaluated against a fixed set of competitors using LLM-as-judge methodology. A strong external judge model (default: `gpt-oss-120b`) acts as an experienced security analyst and scores all model outputs for each incident. Model labels are randomized per incident to prevent position bias.

This extends the [LLM Evaluation Guide](LLM_EVALUATION_GUIDE.md) used for baseline model comparison — the judge criteria, scoring format, and analysis scripts are identical; the only change is adding the finetuned model as a fifth competitor.

Scoring differs by task:
- **Summarization:** single 1–10 quality score per incident
- **Risk assessment:** separate cause analysis score (max 30) and risk assessment score (max 30), summed for ranking (max 60). See [LLM-as-Judge Rubric](LLM_JUDGE_RUBRIC.md) for the full scoring criteria.

---

### Evaluation Pipeline
Four sequential steps, applied identically for any task:

**Step 1 — Inference on the eval split**

The fine-tuned model is served locally via [`serve_model.py`](https://github.com/stratosphereips/Slips-tools/blob/main/unsloth-scripts/serve_model.py) (OpenAI-compatible API on `localhost:8000`) and queried on each incident in the held-out eval split, using the same system prompt and input format as training.

```bash
cd unsloth-scripts/
python3 serve_model.py /path/to/finetuned_model --device cuda --quant 4bit
python3 run_finetuned_inference.py \
  --input filtered_eval.json \
  --output finetuned_eval_results.json \
  --url http://localhost:8000/v1
```

**Step 2 — LLM-as-judge scoring**

The judge receives all five model responses simultaneously and ranks them. The task-specific judge script is used (e.g. `evaluate_summaries.py` for summarization, `evaluate_risk.py` for cause & risk assessment).

```bash
cd alert_summary/
python3 evaluate_summaries.py \
  --input ../unsloth-scripts/finetuned_eval_results.json \
  --output results/finetuned_results.json \
  --judge gpt-oss-120b \
  --base-url http://YOUR_LOCAL_ENDPOINT/v1
```

**Step 3 — Statistical analysis**

```bash
python3 analyze_results.py \
  --results results/finetuned_results.json \
  --summary results/finetuned_report.md \
  --csv results/finetuned_data.csv
```

**Step 4 — Improvement report**

Reads the report and CSV, computes deltas vs. both baselines, identifies the weakest complexity tier and category, and outputs concrete suggestions for data composition and training config.

---

### Baselines and Success Criteria

Two baselines are tracked for any finetuned model:

| Baseline | Role | Success criterion |
|---|---|---|
| Qwen2.5 1B (untuned) | Lower bound — same family, smaller | Finetuned must beat this |
| Qwen2.5 3B (untuned) | Stretch goal — larger, slower on RPi | Finetuned should match or exceed |

The stretch goal tests whether task-specific fine-tuning compensates for parameter count, which determines whether the smaller model can replace the larger one on the Raspberry Pi 5.

---

### Metrics
Three metrics are computed per model:

| Metric | Description |
|---|---|
| **Avg Score** | Mean quality score from the judge (1–10 scale) |
| **Win Rate** | Fraction of incidents where the model ranks 1st |
| **Avg Position** | Mean rank position (lower = better, 1–5 scale) |

---

### Breakdown Dimensions
Results are broken down along two dimensions for every task:

**By incident category:**
- Malware incidents
- Normal traffic incidents

**By incident complexity** (based on event count):
- Simple: < 500 events
- Medium: 500–1999 events
- Complex: ≥ 2000 events

The complexity dimension is particularly relevant for RPi deployment: complex incidents stress the input token budget and expose truncation behavior. A model that performs well on simple/medium but fails on complex incidents has a known, addressable limitation.

---

### Running the Evaluation
The full pipeline (dataset prep → training → inference → eval → report) can be run end-to-end:

```bash
/finetune-eval

# Or jump to evaluation if the model is already trained:
/finetune-eval --skip-to 5
```

---

### Task-Specific Results
| Task | Results Document |
|---|---|
| Incident Summarization | [Summarization Fine-Tuned Model: Evaluation Results](finetuning_results.md) |
| Risk Assessment & Cause Analysis | [Risk Fine-Tuned Model: Evaluation Results](finetuning_risk_results.md) |
| Unified (Summary + Cause + Risk) | [Unified Fine-Tuned Model: Evaluation Results](finetuning_unified_results.md) |
