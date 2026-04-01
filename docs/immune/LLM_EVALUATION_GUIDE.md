# LLM Evaluation Framework Guide

## Overview

This framework implements **LLM-as-a-Judge** methodology for evaluating language model performance on security incident analysis tasks. Rather than relying on manual expert review or simple metrics, we use a local LLM (`gpt-oss-120b`) acting as an experienced network security analyst to systematically assess and compare different models' outputs. The judge model evaluates each response against security-specific criteria, providing comparative rankings (1-4 positions) and quality scores (1-10 scale) with detailed justifications. This approach enables scalable, consistent, and expert-level evaluation across the full dataset of real-world security incidents.

The framework supports two evaluation workflows using identical methodology:

1. **Summarization Evaluation**: Compares incident summary quality across models
2. **Risk Analysis Evaluation**: Compares cause analysis and risk assessment quality across models

Both workflows use comparative ranking where the judge ranks all models' outputs for each incident, avoiding the need for absolute score thresholds.

**Key Features:**
- Full dataset evaluation (532 incidents, stratified Normal/Malware distribution)
- Local judge model via OpenAI-compatible API (no cloud cost)
- Incremental result saving (resumable if interrupted)
- Interactive HTML dashboards with drill-down capabilities

---

## Quick Start

### Setup

```bash
pip install openai python-dotenv
```

No API key required for local endpoints.

### Run Evaluation

```bash
cd alert_summary/

# Summarization workflow
python3 evaluate_summaries.py \
  --input datasets/summarization_dataset_v3.json \
  --output datasets/summarization_dataset_v3_results_oss.json \
  --judge gpt-oss-120b \
  --base-url http://YOUR_LOCAL_ENDPOINT/v1

# Risk analysis workflow
python3 evaluate_risk.py \
  --input datasets/risk_dataset.json \
  --output datasets/risk_dataset_results_oss.json \
  --judge gpt-oss-120b \
  --base-url http://YOUR_LOCAL_ENDPOINT/v1
```

### Analyze Results

```bash
# Summarization
python3 analyze_results.py \
  --results datasets/summarization_dataset_v3_results_oss.json \
  --summary results/summary_report_oss.md \
  --csv results/summary_data_oss.csv \
  --judge gpt-oss-120b

python3 generate_dashboard.py \
  --results datasets/summarization_dataset_v3_results_oss.json \
  --sample datasets/summarization_dataset_v3.json \
  --output results/summary_dashboard_oss.html

# Risk analysis
python3 analyze_results.py \
  --results datasets/risk_dataset_results_oss.json \
  --summary results/risk_report_oss.md \
  --csv results/risk_data_oss.csv \
  --judge gpt-oss-120b

python3 generate_dashboard.py \
  --results datasets/risk_dataset_results_oss.json \
  --sample datasets/risk_dataset.json \
  --output results/risk_dashboard_oss.html

# View results
cat results/summary_report_oss.md
firefox results/summary_dashboard_oss.html
```

---

## Evaluation Workflows

### Workflow 1: Summarization Evaluation

**Purpose:** Compare how well different models generate actionable incident summaries for SOC analysts.

**Methodology:**
- Judge provides comparative **ranking** (1st to 4th place) and **quality scores** (1-10 scale)
- Models evaluated: GPT-4o, GPT-4o-mini, Qwen2.5 1.5B, Qwen2.5 3B
- Dataset: 532 incidents (18 Normal + 514 Malware)

**Evaluation Criteria:**
1. Accuracy of threat identification
2. Completeness of critical events
3. Clarity and readability for SOC analysts
4. Actionability for incident response
5. Professional quality and structure

**Manual Execution:**
```bash
# Step 1: Judge evaluation
python3 evaluate_summaries.py \
  --input datasets/summarization_dataset_v3.json \
  --output datasets/summarization_dataset_v3_results_oss.json \
  --judge gpt-oss-120b \
  --base-url http://YOUR_LOCAL_ENDPOINT/v1

# Step 2: Analyze results
python3 analyze_results.py \
  --results datasets/summarization_dataset_v3_results_oss.json \
  --summary results/summary_report_oss.md \
  --csv results/summary_data_oss.csv \
  --judge gpt-oss-120b

# Step 3: Generate dashboard
python3 generate_dashboard.py \
  --results datasets/summarization_dataset_v3_results_oss.json \
  --output results/summary_dashboard_oss.html
```

**Output Files:**
- `datasets/summarization_dataset_v3_results_oss.json` - Judge rankings
- `results/summary_report_oss.md` - Statistical report
- `results/summary_data_oss.csv` - Spreadsheet export
- `results/summary_dashboard_oss.html` - Interactive visualization

**Results (judge: gpt-oss-120b, 532 incidents):**
```
Rank   Model                Avg Pos    Avg Score    Win Rate
1      GPT-4o-mini          1.66       6.35/10      46.1%
2      GPT-4o               2.02       5.65/10      36.7%
3      Qwen2.5 3B           2.71       4.38/10      15.6%
4      Qwen2.5 1.5B         3.61       2.81/10       1.7%
```

- **Win Rate**: % of times ranked #1
- **Avg Position**: Lower is better (1-4 scale)
- **Avg Score**: Higher is better (1-10 scale)

---

### Workflow 2: Risk Analysis Evaluation

**Purpose:** Compare how well different models perform cause analysis and risk assessment for security incidents.

**Methodology:**
- Judge provides comparative **ranking** (1st to 4th place) and **quality scores** (1-10 scale)
- Models evaluated: GPT-4o, GPT-4o-mini, Qwen2.5 1.5B, Qwen2.5 3B
- Dataset: 532 incidents (18 Normal + 514 Malware)

**Evaluation Criteria:**
1. **Cause Identification Accuracy** - Correctly categorizes as Malicious/Legitimate/Misconfiguration with specific techniques
2. **Evidence-Based Reasoning** - Analysis grounded in DAG evidence, avoids speculation
3. **Risk Level Accuracy** - Appropriate severity classification (Critical/High/Medium/Low)
4. **Business Impact Assessment** - Realistic consequences (data breach, service disruption, compliance)
5. **Investigation Priority** - Actionable guidance aligned with risk and impact

**Manual Execution:**
```bash
# Step 1: Judge evaluation
python3 evaluate_risk.py \
  --input datasets/risk_dataset.json \
  --output datasets/risk_dataset_results_oss.json \
  --judge gpt-oss-120b \
  --base-url http://YOUR_LOCAL_ENDPOINT/v1

# Step 2: Analyze results
python3 analyze_results.py \
  --results datasets/risk_dataset_results_oss.json \
  --summary results/risk_report_oss.md \
  --csv results/risk_data_oss.csv \
  --judge gpt-oss-120b

# Step 3: Generate dashboard
python3 generate_dashboard.py \
  --results datasets/risk_dataset_results_oss.json \
  --output results/risk_dashboard_oss.html
```

**Output Files:**
- `datasets/risk_dataset_results_oss.json` - Judge rankings and scores
- `results/risk_report_oss.md` - Statistical report
- `results/risk_data_oss.csv` - Spreadsheet export
- `results/risk_dashboard_oss.html` - Interactive visualization

**Results (judge: gpt-oss-120b, 532 incidents):**
```
Rank   Model          Avg Pos    Avg Score    Win Rate
1      GPT-4o          1.46       7.98/10      65.6%
2      GPT-4o-mini     1.92       7.34/10      26.3%
3      Qwen2.5 3B      3.08       5.33/10       4.9%
4      Qwen2.5         3.54       4.29/10       3.2%
```

**By Incident Category:**
```
Malware (514 incidents):
  1. GPT-4o        avg pos 1.45   score 8.08   wins 342
  2. GPT-4o-mini   avg pos 1.91   score 7.43   wins 134
  3. Qwen2.5 3B    avg pos 3.08   score 5.39   wins  25
  4. Qwen2.5       avg pos 3.56   score 4.30   wins  13

Normal (18 incidents):
  1. GPT-4o        avg pos 1.83   score 5.17   wins   7
  2. GPT-4o-mini   avg pos 2.00   score 4.89   wins   6
  3. Qwen2.5       avg pos 2.89   score 4.00   wins   4
  4. Qwen2.5 3B    avg pos 3.28   score 3.56   wins   1
```

**By Incident Complexity:**
```
Simple (<500 events, 324 incidents):
  1. GPT-4o        avg pos 1.57   score 7.76   wins 193
  2. GPT-4o-mini   avg pos 1.91   score 7.29   wins  98

Medium (500-2000 events, 62 incidents):
  1. GPT-4o        avg pos 1.23   score 8.31   wins  49
  2. GPT-4o-mini   avg pos 1.94   score 7.39   wins  11

Complex (>2000 events, 146 incidents):
  1. GPT-4o        avg pos 1.32   score 8.32   wins 107
  2. GPT-4o-mini   avg pos 1.91   score 7.44   wins  31
```

- **Win Rate**: % of times ranked #1
- **Avg Position**: Lower is better (1-4 scale)
- **Avg Score**: Higher is better (1-10 scale)

**Key observations:**
- GPT-4o dominates risk analysis across all complexity levels — unlike summarization where GPT-4o-mini wins
- GPT-4o's advantage grows with complexity: win rate goes from 59.6% (simple) to 73.3% (complex)
- Qwen2.5 7B underperforms its own 3B variant on risk analysis (avg pos 3.54 vs 3.08)
- On Normal incidents, the gap between GPT-4o and GPT-4o-mini narrows significantly

---

## CLI Reference

### evaluate_summaries.py / evaluate_risk.py

| Argument | Default | Description |
|----------|---------|-------------|
| `--input`, `-i` | `datasets/summarization_dataset_v3.json` / `datasets/risk_dataset.json` | Input dataset |
| `--output`, `-o` | `results/summary_results.json` / `results/risk_results.json` | Output results |
| `--judge`, `-j` | `gpt-4o` | Judge model name |
| `--base-url` | OpenAI default | Base URL for OpenAI-compatible API |
| `--api-key` | `OPENAI_API_KEY` env var | API key (optional for local endpoints) |

### analyze_results.py

| Argument | Default | Description |
|----------|---------|-------------|
| `--results`, `-r` | `results/summary_results.json` | Input results file |
| `--summary`, `-s` | `results/summary_report.md` | Output Markdown report |
| `--csv`, `-c` | `results/summary_data.csv` | Output CSV file |
| `--judge`, `-j` | `GPT-4o` | Judge name shown in report |

---

For detailed dataset generation instructions, see [README_dataset_summary_workflow.md](README_dataset_summary_workflow.md) and [README_dataset_risk_workflow.md](README_dataset_risk_workflow.md).
