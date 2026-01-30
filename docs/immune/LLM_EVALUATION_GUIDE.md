# LLM Evaluation Framework Guide

## Overview

This framework implements **LLM-as-a-Judge** methodology for evaluating language model performance on security incident analysis tasks. Rather than relying on manual expert review or simple metrics, we use a powerful LLM (GPT-4o) acting as an experienced network security analyst to systematically assess and compare different models' outputs. The judge model evaluates each response against security-specific criteria, providing comparative rankings (1-4 positions) and quality scores (1-10 scale) with detailed justifications. This approach enables scalable, consistent, and expert-level evaluation of multiple models across dozens of real-world security incidents.

The framework supports two evaluation workflows using identical methodology:

1. **Summarization Evaluation**: Compares incident summary quality across models
2. **Risk Analysis Evaluation**: Compares cause analysis and risk assessment quality across models

Both workflows use comparative ranking where the judge ranks all models' outputs for each incident, avoiding the need for absolute score thresholds.

**Key Features:**
- 50-sample evaluations (stratified Normal/Malware distribution)
- Interactive HTML dashboards with drill-down capabilities
- Cost-effective (~$5 per 50-incident evaluation with GPT-4o judge)
- Reproducible methodology with configurable parameters

---

## Quick Start

### Setup

```bash
pip install openai python-dotenv
export OPENAI_API_KEY="sk-your-key-here"
```

### Run Complete Evaluation

```bash
# Summarization workflow
./run_evaluation_summary.sh

# Risk analysis workflow
./run_evaluation_risk.sh

# View results
cat results/summary_report.md  # or results/risk_summary.md
firefox results/summary_dashboard.html  # or results/risk_dashboard.html
```

### Test Before Full Run

```bash
# Single incident test (~$0.10)
python3 test_evaluation.py
```

---

## Evaluation Workflows

### Workflow 1: Summarization Evaluation

**Purpose:** Compare how well different models generate actionable incident summaries for SOC analysts.

**Methodology:**
- Judge provides comparative **ranking** (1st to 4th place) and **quality scores** (1-10 scale)
- Models evaluated: GPT-4o, GPT-4o-mini, Qwen2.5 15B, Qwen2.5 3B
- Dataset: 50 incidents (10 Normal + 40 Malware)

**Evaluation Criteria:**
1. Accuracy of threat identification
2. Completeness of critical events
3. Clarity and readability for SOC analysts
4. Actionability for incident response
5. Professional quality and structure

**Manual Execution:**
```bash
# Step 1: Sample incidents
python3 datasets/create_evaluation_sample.py [--size 50] [--seed 42]

# Step 2: Judge evaluation
python3 evaluate_summaries.py [--judge gpt-4o] [--input FILE] [--output FILE]

# Step 3: Analyze results
python3 analyze_results.py [--results FILE] [--summary FILE] [--csv FILE]

# Step 4: Generate dashboard
python3 generate_dashboard.py [--results FILE] [--sample FILE] [--output FILE]
```

**Output Files:**
- `datasets/summary_sample.json` - Sampled incidents
- `results/summary_results.json` - Judge rankings
- `results/summary_report.md` - Statistical report
- `results/summary_data.csv` - Spreadsheet export
- `results/summary_dashboard.html` - Interactive visualization

**Example Results:**
```
Rank   Model                Avg Pos    Avg Score    Win Rate
1      GPT-4o               1.8        8.5          45.0%
2      Qwen2.5 15B          2.3        7.2          28.0%
3      GPT-4o-mini          2.7        6.8          18.0%
4      Qwen2.5 3B           3.2        5.9          9.0%
```

- **Win Rate**: % of times ranked #1
- **Avg Position**: Lower is better (1-4 scale)
- **Avg Score**: Higher is better (1-10 scale)

---

### Workflow 2: Risk Analysis Evaluation

**Purpose:** Compare how well different models perform cause analysis and risk assessment for security incidents.

**Methodology:**
- Judge provides comparative **ranking** (1st to 4th place) and **quality scores** (1-10 scale)
- Models evaluated: GPT-4o, GPT-4o-mini, Qwen2.5, Qwen2.5 3B
- Dataset: 50 incidents (18 Normal + 32 Malware)

**Evaluation Criteria:**
1. **Cause Identification Accuracy** - Correctly categorizes as Malicious/Legitimate/Misconfiguration with specific techniques
2. **Evidence-Based Reasoning** - Analysis grounded in DAG evidence, avoids speculation
3. **Risk Level Accuracy** - Appropriate severity classification (Critical/High/Medium/Low)
4. **Business Impact Assessment** - Realistic consequences (data breach, service disruption, compliance)
5. **Investigation Priority** - Actionable guidance aligned with risk and impact

**Manual Execution:**
```bash
# Step 1: Sample incidents
python3 datasets/create_risk_sample.py [--size 50] [--seed 42]

# Step 2: Judge evaluation
python3 evaluate_risk.py [--input FILE] [--judge gpt-4o] [--output FILE]

# Step 3: Analyze results
python3 analyze_results.py --results results/risk_results.json --summary results/risk_summary.md

# Step 4: Generate dashboard
python3 generate_dashboard.py --results results/risk_results.json --output results/risk_dashboard.html
```

**Output Files:**
- `datasets/risk_sample.json` - Sampled incidents
- `results/risk_results.json` - Judge rankings and scores
- `results/risk_summary.md` - Statistical report
- `results/risk_data.csv` - Spreadsheet export
- `results/risk_dashboard.html` - Interactive visualization

**Example Results:**
```
Rank   Model                     Avg Pos    Avg Score    Win Rate
1      cause_risk_gpt4o          1.8        8.2          42.0%
2      cause_risk_gpt4o_mini     2.4        7.5          26.0%
3      cause_risk_qwen2_5        2.9        6.8          20.0%
4      cause_risk_qwen2_5_3b     3.1        6.1          12.0%
```

- **Win Rate**: % of times ranked #1
- **Avg Position**: Lower is better (1-4 scale)
- **Avg Score**: Higher is better (1-10 scale)

---

For detailed dataset generation instructions, see [README_SUMMARY_WORKFLOW.md](README_SUMMARY_WORKFLOW.md) and [README_RISK_WORKFLOW.md](README_RISK_WORKFLOW.md).
