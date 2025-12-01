# Dataset Generation Workflows: Quick Comparison

## Overview

The alert_summary toolkit provides **two complementary workflows** for generating LLM-enhanced security datasets from Slips alerts:

1. **Summarization Workflow** - Event summarization and behavior pattern analysis
2. **Cause & Risk Analysis Workflow** - Root cause analysis and risk assessment

Both workflows share the same initial steps (sampling + DAG generation) but produce different analytical outputs.

---

## Which Workflow Should I Use?

| If you need... | Use This Workflow |
|----------------|-------------------|
| **Event summaries** in plain language | Summarization |
| **Behavior pattern** analysis (network flows, activities) | Summarization |
| **Root cause** analysis (malicious/legitimate/misconfigured) | Cause & Risk |
| **Risk assessment** with business impact and priority | Cause & Risk |
| **Both types of analysis** | Run both workflows! They're compatible. |

---

## Workflow Comparison

### Summarization Workflow

**Purpose:** Transform technical security events into human-readable summaries and structured behavior analyses.

**Output:** `summary` (event description) + `behavior_analysis` (network flows, activity patterns)

**Use Cases:**
- Security analyst briefings
- Incident timeline reconstruction
- Behavior pattern recognition
- Training data for summarization models

**Documentation:** [README_dataset_summary_workflow.md](README_dataset_summary_workflow.md)

**Quick Start:**
```bash
./sample_dataset.sh 100 my_dataset --seed 42
./generate_dag_analysis.sh datasets/my_dataset.jsonl
./generate_llm_analysis.sh datasets/my_dataset.jsonl --model gpt-4o-mini --group-events --behavior-analysis
python3 correlate_incidents.py datasets/my_dataset.*.json --jsonl datasets/my_dataset.jsonl -o final_dataset.json
```

---

### Cause & Risk Analysis Workflow

**Purpose:** Analyze root causes and assess security risks with structured business impact evaluation.

**Output:** `cause_analysis` (3-category causes) + `risk_assessment` (risk level, business impact, priority)

**Use Cases:**
- Incident response prioritization
- Root cause investigation
- Risk-based decision making
- Training data for risk assessment models

**Documentation:** [README_dataset_risk_workflow.md](README_dataset_risk_workflow.md)

**Quick Start:**
```bash
./sample_dataset.sh 100 my_dataset --seed 42
./generate_dag_analysis.sh datasets/my_dataset.jsonl
./generate_cause_risk_analysis.sh datasets/my_dataset.jsonl --model gpt-4o-mini --group-events
python3 correlate_risks.py datasets/my_dataset.*.json --jsonl datasets/my_dataset.jsonl -o final_dataset_risk.json
```

---

## Running Both Workflows

Both workflows can be run on the same dataset to produce comprehensive multi-perspective analysis:

```bash
# Step 1-2: Shared (run once)
./sample_dataset.sh 100 my_dataset --seed 42
./generate_dag_analysis.sh datasets/my_dataset.jsonl

# Step 3a: Summarization analysis
./generate_llm_analysis.sh datasets/my_dataset.jsonl \
  --model gpt-4o-mini --group-events --behavior-analysis

# Step 3b: Cause & Risk analysis
./generate_cause_risk_analysis.sh datasets/my_dataset.jsonl \
  --model gpt-4o-mini --group-events

# Step 4: Correlate ALL analyses (use correlate_risks.py for broader support)
python3 correlate_risks.py datasets/my_dataset.*.json \
  --jsonl datasets/my_dataset.jsonl \
  -o final_dataset_complete.json
```

**Result:** Dataset with DAG + Summarization + Cause & Risk analyses per incident.

---

## Key Differences

| Aspect | Summarization | Cause & Risk |
|--------|---------------|--------------|
| **Generation Script** | `generate_llm_analysis.sh` | `generate_cause_risk_analysis.sh` |
| **Correlation Script** | `correlate_incidents.py` | `correlate_risks.py` |
| **Prompt Focus** | Event clarity and behavior patterns | Root causes and risk evaluation |
| **Output Structure** | `summary` + `behavior_analysis` | `cause_analysis` + `risk_assessment` |
| **Evaluation Method** | Summarization quality metrics | Risk assessment accuracy |
| **Best For** | Understanding WHAT happened | Understanding WHY and RISK level |

---

## Shared Components

Both workflows use the same:
- ✅ Sampling methodology (`sample_dataset.sh`)
- ✅ DAG structural analysis (`generate_dag_analysis.sh`)
- ✅ Event grouping optimization (`--group-events`)
- ✅ Multi-model support (GPT-4o, Qwen, etc.)
- ✅ JSONL/IDEA format parsing
- ✅ Category labeling system

---

## Next Steps

Choose your workflow:
- **Summarization**: [README_dataset_summary_workflow.md](README_dataset_summary_workflow.md)
- **Cause & Risk**: [README_dataset_risk_workflow.md](README_dataset_risk_workflow.md)
- **Evaluation**: [LLM_EVALUATION_GUIDE.md](LLM_EVALUATION_GUIDE.md)

Or run both for comprehensive analysis!
