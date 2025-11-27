# Network Event Cause & Risk Analysis Dataset for Slips IDS

## Table of Contents

- [1. Task Description](#1-task-description)
- [2. Relationship to Summarization Workflow](#2-relationship-to-summarization-workflow)
- [3. Dataset Generation Workflow](#3-dataset-generation-workflow)
  - [Workflow Overview](#workflow-overview)
  - [Stage 3: Multi-Model Cause & Risk Analysis](#stage-3-multi-model-cause--risk-analysis)
  - [Stage 4: Dataset Correlation](#stage-4-dataset-correlation)
  - [Dataset Structure](#dataset-structure)
- [4. Use Cases and Applications](#4-use-cases-and-applications)

## 1. Task Description

Develop a dataset for **root cause analysis and risk assessment** of network security incidents from Slips IDS alerts. This complementary workflow focuses on structured security analysis rather than event summarization, providing:

1. **Cause Analysis** - Categorized incident attribution (Malicious Activity / Legitimate Activity / Misconfigurations)
2. **Risk Assessment** - Structured evaluation (Risk Level / Business Impact / Investigation Priority)

**Target Deployment**: Same hardware constraints as [summarization workflow](DATASET_REPORT.md#2-limitations) (Raspberry Pi 5, 1.5B-3B parameter models).

## 2. Relationship to Summarization Workflow

Both workflows share identical **Stages 1-2** (incident sampling and DAG generation) but diverge in LLM analysis approach:

| Aspect | Summarization Workflow | Risk Analysis Workflow |
|--------|------------------------|------------------------|
| **Documentation** | [DATASET_REPORT.md](DATASET_REPORT.md) | This document |
| **Detailed Guide** | [README_dataset_summary_workflow.md](README_dataset_summary_workflow.md) | [README_dataset_risk_workflow.md](README_dataset_risk_workflow.md) |
| **Analysis Script** | `generate_llm_analysis.sh` | `generate_cause_risk_analysis.sh` |
| **Correlation Script** | `correlate_incidents.py` | `correlate_risks.py` |
| **Output Fields** | `summary` + `behavior_analysis` | `cause_analysis` + `risk_assessment` |
| **LLM Prompts** | 2 per incident (event summarization + behavior patterns) | 2 per incident (cause attribution + risk scoring) |
| **Primary Use Case** | Incident timeline reconstruction, behavior pattern identification | Root cause analysis, threat prioritization, SOC decision support |

**Recommendation**: Generate both datasets from the same sampled incidents to enable comparative analysis and multi-task model training.

## 3. Dataset Generation Workflow

### Workflow Overview

**Stages 1-2** (Sampling + DAG): See [DATASET_REPORT.md §3](DATASET_REPORT.md#3-dataset-generation-workflow) - identical to summarization workflow.

**Quick commands:**
```bash
# Stage 1: Sample 100 incidents
./sample_dataset.sh 100 my_dataset --seed 42

# Stage 2: Generate DAG analysis
./generate_dag_analysis.sh datasets/my_dataset.jsonl
```

### Stage 3: Multi-Model Cause & Risk Analysis

Query LLMs with dual prompts for cause attribution and risk assessment:

```bash
# GPT-4o-mini (recommended baseline)
./generate_cause_risk_analysis.sh datasets/my_dataset.jsonl \
  --model gpt-4o-mini --group-events

# Qwen2.5:3b (target deployment model)
./generate_cause_risk_analysis.sh datasets/my_dataset.jsonl \
  --model qwen2.5:3b \
  --base-url http://10.147.20.102:11434/v1 --group-events
```

**Output Structure** (per incident):
```json
{
  "cause_analysis": "**Possible Causes:**\n\n**1. Malicious Activity:**\n• Port scanning indicates reconnaissance...\n\n**2. Legitimate Activity:**\n• Could be network monitoring tools...\n\n**3. Misconfigurations:**\n• Firewall allowing unrestricted scanning...\n\n**Conclusion:** Most likely malicious reconnaissance activity.",

  "risk_assessment": "**Risk Level:** High\n\n**Justification:** Active scanning + C2 connections...\n\n**Business Impact:** Potential data breach or service disruption...\n\n**Likelihood of Malicious Activity:** High - Systematic attack pattern...\n\n**Investigation Priority:** Immediate - Block source IP and investigate."
}
```

### Stage 4: Dataset Correlation

Merge all analyses (DAG + LLM cause/risk assessments) by incident ID:

```bash
python3 correlate_risks.py datasets/my_dataset.*.json \
  --jsonl datasets/my_dataset.jsonl \
  -o datasets/final_dataset_risk.json
```

### Dataset Structure

Final output contains merged analyses with model-specific risk assessments:

```json
{
  "total_incidents": 100,
  "incidents": [
    {
      "incident_id": "uuid",
      "category": "Malware",
      "source_ip": "192.168.1.113",
      "timewindow": "5",
      "timeline": "2024-04-05 16:53:07 to 16:53:50",
      "threat_level": 15.36,
      "event_count": 4604,
      "dag_analysis": "• 16:53 - 222 horizontal port scans [HIGH]\n...",
      "cause_risk_gpt_4o_mini": {
        "cause_analysis": "**1. Malicious Activity:** Reconnaissance scanning...",
        "risk_assessment": "**Risk Level:** High\n**Justification:**..."
      },
      "cause_risk_gpt_4o": { ... },
      "cause_risk_qwen2_5": { ... }
    }
  ]
}
```

**Key differences from summarization dataset**:
- `cause_risk_*` fields replace `llm_*` fields
- Structured 3-category cause analysis (vs. free-form summary)
- 5-field risk assessment framework (vs. behavior flow description)

## 4. Use Cases and Applications

### Security Operations Center (SOC)
- **Automated Triage**: Risk level + investigation priority for alert queue sorting
- **Incident Attribution**: Distinguish malicious attacks from misconfigurations
- **Resource Allocation**: Business impact assessment for team assignments

### Model Training Applications
- **Classification Tasks**: Train models to categorize incidents (malicious/legitimate/misconfiguration)
- **Risk Scoring**: Fine-tune models for threat level prediction
- **Decision Support**: Generate actionable recommendations (block/monitor/investigate)

### Dataset Comparison
Use both workflows together:
- **Summarization**: "What happened?" (temporal sequences, behavior patterns)
- **Risk Analysis**: "Why did it happen?" + "How urgent?" (attribution, prioritization)

**Combined Training Strategy**:
```bash
# Generate both datasets from same incidents
./generate_llm_analysis.sh datasets/my_dataset.jsonl --model qwen2.5:3b --group-events --behavior-analysis
./generate_cause_risk_analysis.sh datasets/my_dataset.jsonl --model qwen2.5:3b --group-events

# Correlate separately
python3 correlate_incidents.py datasets/my_dataset.*.json --jsonl datasets/my_dataset.jsonl -o summary_dataset.json
python3 correlate_risks.py datasets/my_dataset.*.json --jsonl datasets/my_dataset.jsonl -o risk_dataset.json

# Multi-task training: Merge datasets and train single model on both tasks
```

---

**For detailed implementation**: See [README_dataset_risk_workflow.md](README_dataset_risk_workflow.md)
**For workflow comparison**: See [WORKFLOWS_OVERVIEW.md](WORKFLOWS_OVERVIEW.md) (if available)
**For evaluation methods**: See [LLM_EVALUATION_GUIDE.md](LLM_EVALUATION_GUIDE.md)
