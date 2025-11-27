# Cause & Risk Analysis Workflow

## Overview

The **Cause & Risk Analysis workflow** generates structured security analysis for Slips incidents using LLM-powered assessment. For each incident, it produces:

1. **Cause Analysis** - Categorized possible reasons (Malicious Activity / Legitimate Activity / Misconfigurations)
2. **Risk Assessment** - Structured evaluation (Risk Level / Business Impact / Investigation Priority)

This workflow is complementary to the [Summarization workflow](README_dataset_summary_workflow.md), which focuses on event summarization and behavior analysis.

---

## Workflow Comparison

| Aspect | Summarization Workflow | Risk Analysis Workflow |
|--------|------------------------|------------------------|
| **Script** | `generate_llm_analysis.sh` | `generate_cause_risk_analysis.sh` |
| **Correlation** | `correlate_incidents.py` | `correlate_risks.py` |
| **Output Fields** | `summary` + `behavior_analysis` | `cause_analysis` + `risk_assessment` |
| **LLM Calls** | 2 per incident (summary + behavior) | 2 per incident (cause + risk) |
| **Steps 1-2** | Identical (sampling + DAG) | Identical (sampling + DAG) |
| **Use Case** | Event summarization, behavior patterns | Root cause analysis, risk prioritization |

---

## Prerequisites

- Python 3.6+ with dependencies: `openai`, `python-dotenv`
- `OPENAI_API_KEY` environment variable set
- Access to OpenAI-compatible API (OpenAI, Ollama, etc.)

For initial setup and shared steps, see [README_dataset_summary_workflow.md](README_dataset_summary_workflow.md).

---

## Workflow Steps

### Steps 1-2: Sampling & DAG Generation (Shared)

These steps are **identical** to the Summarization workflow. See:
- [Step 1: Sample Incidents](README_dataset_summary_workflow.md#321-step-1-sample-representative-incidents)
- [Step 2: Generate DAG Analysis](README_dataset_summary_workflow.md#322-step-2-generate-dag-structural-analysis)

**Quick commands:**
```bash
# Step 1: Sample 100 incidents
./sample_dataset.sh 100 my_dataset --seed 42

# Step 2: Generate DAG analysis
./generate_dag_analysis.sh datasets/my_dataset.jsonl
```

---

### Step 3: Generate Cause & Risk Analysis (Multiple Models)

Use `generate_cause_risk_analysis.sh` to generate both cause and risk assessments for each incident.

**Basic usage:**
```bash
./generate_cause_risk_analysis.sh datasets/my_dataset.jsonl \
  --model gpt-4o-mini \
  --group-events
```

**Multi-model analysis (recommended):**
```bash
# GPT-4o-mini (fast, cost-effective)
./generate_cause_risk_analysis.sh datasets/my_dataset.jsonl \
  --model gpt-4o-mini \
  --group-events

# GPT-4o (higher quality)
./generate_cause_risk_analysis.sh datasets/my_dataset.jsonl \
  --model gpt-4o \
  --group-events

# Qwen 2.5 3B via Ollama (local, free)
./generate_cause_risk_analysis.sh datasets/my_dataset.jsonl \
  --model qwen2.5:3b \
  --base-url http://10.147.20.102:11434/v1 \
  --group-events

# Qwen 2.5 1.5B via Ollama (faster local alternative)
./generate_cause_risk_analysis.sh datasets/my_dataset.jsonl \
  --model qwen2.5:1.5b \
  --base-url http://10.147.20.102:11434/v1 \
  --group-events
```

**Output files:**
- `datasets/my_dataset.cause_risk.gpt-4o-mini.json`
- `datasets/my_dataset.cause_risk.gpt-4o.json`
- `datasets/my_dataset.cause_risk.qwen2_5.json`

**Key options:**
- `--group-events`: Groups similar events to reduce token usage (recommended for large incidents)
- `--verbose`: Show detailed progress and token counts
- `--incident-id <UUID>`: Analyze specific incident only

---

### Step 4: Correlate All Analyses

Use `correlate_risks.py` to merge DAG, LLM, and Cause & Risk analyses into a unified dataset.

```bash
python3 correlate_risks.py \
  datasets/my_dataset.*.json \
  --jsonl datasets/my_dataset.jsonl \
  -o datasets/final_dataset_risk.json
```

This creates a consolidated JSON file with all analyses merged by incident ID.

---

## Complete Pipeline Example

```bash
#!/bin/bash
# Full Cause & Risk Analysis Pipeline

DATASET_NAME="my_dataset_risk"
NUM_SAMPLES=100

# Step 1: Sample incidents
./sample_dataset.sh $NUM_SAMPLES $DATASET_NAME --seed 42

# Step 2: Generate DAG analysis
./generate_dag_analysis.sh datasets/${DATASET_NAME}.jsonl

# Step 3: Generate Cause & Risk analysis (multiple models)
./generate_cause_risk_analysis.sh datasets/${DATASET_NAME}.jsonl \
  --model gpt-4o-mini --group-events

./generate_cause_risk_analysis.sh datasets/${DATASET_NAME}.jsonl \
  --model gpt-4o --group-events

./generate_cause_risk_analysis.sh datasets/${DATASET_NAME}.jsonl \
  --model qwen2.5:3b \
  --base-url http://10.147.20.102:11434/v1 \
  --group-events

# Step 4: Correlate all analyses
python3 correlate_risks.py \
  datasets/${DATASET_NAME}.*.json \
  --jsonl datasets/${DATASET_NAME}.jsonl \
  -o datasets/final_${DATASET_NAME}.json

echo "Pipeline complete! Output: datasets/final_${DATASET_NAME}.json"
```

---

## Output Dataset Structure

The final dataset contains merged analyses with the following structure:

```json
{
  "total_incidents": 100,
  "incidents": [
    {
      "incident_id": "abc123-def456-...",
      "category": "Malware",
      "source_ip": "10.0.2.15",
      "timewindow": "12",
      "timeline": "2024-04-05 16:53:07 to 16:53:50",
      "threat_level": 15.36,
      "event_count": 4604,
      "dag_analysis": "...",
      "cause_risk_gpt4o_mini": {
        "cause_analysis": "**Possible Causes:**\n\n**1. Malicious Activity:**\n• Reconnaissance scanning...\n\n**2. Legitimate Activity:**\n• Network monitoring...\n\n**3. Misconfigurations:**\n• Firewall misconfiguration...\n\n**Conclusion:** Most likely malicious reconnaissance...",
        "risk_assessment": "**Risk Level:** High\n\n**Justification:** Active port scanning indicates potential attack preparation...\n\n**Business Impact:** Could lead to service disruption or data breach...\n\n**Likelihood of Malicious Activity:** High - Systematic scanning pattern...\n\n**Investigation Priority:** High - Investigate source and block if confirmed malicious"
      },
      "cause_risk_gpt4o": { ... },
      "cause_risk_qwen2_5": { ... }
    }
  ]
}
```

**Field descriptions:**
- `cause_analysis`: Structured analysis with 3 categories (Malicious/Legitimate/Misconfigurations) + Conclusion
- `risk_assessment`: 5-field assessment (Risk Level, Justification, Business Impact, Likelihood, Investigation Priority)

---

## Evaluation Workflow

After generating the dataset, evaluate LLM performance using LLM-as-judge:

```bash
# Evaluate risk assessments
python3 evaluate_risk.py datasets/final_dataset_risk.json \
  --judge-model gpt-4o \
  -o risk_evaluation_results.json
```

For detailed evaluation instructions, see [LLM_EVALUATION_GUIDE.md](LLM_EVALUATION_GUIDE.md#risk-analysis-evaluation).

---

## Performance Considerations

**Token Optimization:**
- Use `--group-events` to reduce token usage by 96-99% for large incidents
- Without grouping: 4604 events → ~200K tokens
- With grouping: 4604 events → ~5K tokens

**Model Selection:**
- **GPT-4o-mini**: Best balance of cost/quality for production
- **GPT-4o**: Highest quality, ~10x cost of mini
- **Qwen 2.5**: Free local alternative via Ollama

**Parallel Processing:**
Run multiple models concurrently to reduce total pipeline time:
```bash
# Run in parallel (requires multiple terminals or background jobs)
./generate_cause_risk_analysis.sh datasets/my_dataset.jsonl --model gpt-4o-mini --group-events &
./generate_cause_risk_analysis.sh datasets/my_dataset.jsonl --model qwen2.5:3b --base-url http://localhost:11434/v1 --group-events &
wait
```

---

## Next Steps

- **Evaluation**: [LLM_EVALUATION_GUIDE.md](LLM_EVALUATION_GUIDE.md) - Evaluate analysis quality
- **Summarization Workflow**: [README_dataset_summary_workflow.md](README_dataset_summary_workflow.md) - Alternative workflow
- **Comparison**: [WORKFLOWS_OVERVIEW.md](WORKFLOWS_OVERVIEW.md) - Choose the right workflow

For questions or issues, see the main [README.md](../README.md).
