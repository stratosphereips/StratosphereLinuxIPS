# LLM Evaluation Framework Guide

## Overview

Evaluate 4 LLM models (GPT-4o, GPT-4o-mini, Qwen2.5 15B, Qwen2.5) on security incident summarization using GPT-4o as a network security analyst judge.

- 50-sample evaluation (10 Normal + 40 Malware)
- Comparative ranking (1-4) with scores (1-10)
- Interactive HTML dashboard
- Cost: ~$5 for 50 evaluations

---

## Quick Start

### Setup

```bash
pip install openai python-dotenv
export OPENAI_API_KEY="sk-your-key-here"
```

### Run Evaluation

```bash
# Summarization workflow
./run_evaluation_summary.sh

# Risk analysis workflow
./run_evaluation_risk.sh

# OR manual steps
python3 datasets/create_evaluation_sample.py
python3 evaluate_summaries.py
python3 analyze_results.py
python3 generate_dashboard.py

# View results
cat results/summary_report.md
firefox results/summary_dashboard.html
```

### Test First

```bash
# Single incident test (~$0.10)
python3 test_evaluation.py
```

---

## Components

### 1. Dataset Sampler
```bash
python3 datasets/create_evaluation_sample.py [--size 50] [--seed 42]
```
Output: `datasets/summary_sample.json`

### 2. Judge Evaluation
```bash
python3 evaluate_summaries.py [--judge gpt-4o] [--input FILE] [--output FILE]
```
Output: `results/summary_results.json`

### 3. Results Analysis
```bash
python3 analyze_results.py [--results FILE] [--summary FILE] [--csv FILE]
```
Output: `results/summary_report.md` (Markdown), `results/summary_data.csv`

### 4. Dashboard Generator
```bash
python3 generate_dashboard.py [--results FILE] [--sample FILE] [--output FILE]
```
Output: `results/summary_dashboard.html`

**All scripts support `--help` for full options.**

---

## Example Workflows

### Standard Evaluation (50 samples, ~$5)
```bash
python3 datasets/create_evaluation_sample.py
python3 evaluate_summaries.py
python3 analyze_results.py
python3 generate_dashboard.py
firefox results/summary_dashboard.html
```

### Budget Evaluation (GPT-4o-mini judge, ~$1)
```bash
python3 datasets/create_evaluation_sample.py
python3 evaluate_summaries.py --judge gpt-4o-mini
python3 analyze_results.py
```

### Large-Scale Evaluation (100 samples, ~$10)
```bash
python3 datasets/create_evaluation_sample.py --size 100 -o datasets/sample_100.json
python3 evaluate_summaries.py -i datasets/sample_100.json -o results/results_100.json
python3 analyze_results.py -r results/results_100.json -s results/summary_100.md
python3 generate_dashboard.py -r results/results_100.json -s datasets/sample_100.json
```

### Compare Judge Models
```bash
python3 datasets/create_evaluation_sample.py

# GPT-4o judge
python3 evaluate_summaries.py --judge gpt-4o -o results/eval_gpt4o.json
python3 analyze_results.py -r results/eval_gpt4o.json -s results/summary_gpt4o.md

# GPT-4o-mini judge
python3 evaluate_summaries.py --judge gpt-4o-mini -o results/eval_mini.json
python3 analyze_results.py -r results/eval_mini.json -s results/summary_mini.md

# Compare
diff results/summary_gpt4o.md results/summary_mini.md
```

---

## Dashboard Features

- **Summary Metrics**: Total incidents, top performer, win rate
- **Win Rate Chart**: Bar chart comparing models
- **Position Distribution**: 1st/2nd/3rd/4th place frequency
- **Category Performance**: Malware vs Normal breakdown
- **Head-to-Head Matrix**: Pairwise win rates
- **Incident Browser**: Searchable table with expandable details

**Interactive:** Click rows for full details, search/filter, dark/light theme

---

## Understanding Results

### Example Output
```
Rank   Model                Avg Pos    Avg Score    Win Rate
1      GPT-4o               1.8        8.5          45.0%
2      Qwen2.5 15B          2.3        7.2          28.0%
3      GPT-4o-mini          2.7        6.8          18.0%
4      Qwen2.5              3.2        5.9          9.0%
```

- **Win Rate**: % of times ranked #1
- **Avg Position**: 1-4 scale (lower is better)
- **Avg Score**: 1-10 scale (higher is better)

---

## Evaluation Criteria

Judge (GPT-4o as network analyst) evaluates:
1. Accuracy of threat identification
2. Completeness of critical events
3. Clarity and readability
4. Actionability for incident response
5. Professional quality for SOC

Output: Rankings + scores + justification

---

## Tips

### Cost Optimization
- Test with `test_evaluation.py` first ($0.10)
- Use `--judge gpt-4o-mini` for testing (80% cheaper)
- Start with 25-50 samples

### Organization
```bash
mkdir -p experiments/exp01
python3 datasets/create_evaluation_sample.py -o experiments/exp01/sample.json
python3 evaluate_summaries.py -i experiments/exp01/sample.json -o experiments/exp01/results.json
# ... continue workflow in exp01/
```

### Batch Processing
```bash
for size in 25 50 100; do
  python3 datasets/create_evaluation_sample.py --size $size -o datasets/sample_${size}.json
  python3 evaluate_summaries.py -i datasets/sample_${size}.json -o results/eval_${size}.json
done
```

---

## Troubleshooting

**API Key:**
```bash
echo $OPENAI_API_KEY
export OPENAI_API_KEY="sk-..."
```

**Rate Limits:** Add `time.sleep(2)` in `evaluate_summaries.py`

**Dashboard:** Requires internet for CDN (Chart.js, Bootstrap)

---

## Files Generated

```
datasets/summary_sample.json           # 50 sampled incidents
results/summary_results.json           # Judge rankings
results/summary_report.md              # Markdown report
results/summary_data.csv               # Spreadsheet data
results/summary_dashboard.html         # Interactive visualization
```

---

## Dataset Composition

**Summarization Dataset:**
- Normal: 10 samples (20% - all available)
- Malware: 40 samples (80%)
- Event count: 24 - 7,322 (avg: 1,518)
- Stratified by complexity

**Risk Analysis Dataset:**
- Normal: 18 samples (36% - all available)
- Malware: 32 samples (64%)
- Models: GPT-4o, GPT-4o-mini, Qwen2.5, Qwen2.5 3B
- Fields: cause_analysis + risk_assessment

---

## Risk Analysis Evaluation

Alternative workflow for evaluating **Cause & Risk analysis** outputs using LLM-as-judge methodology.

This workflow evaluates how well LLMs perform root cause analysis and risk assessment for security incidents. For dataset generation, see [README_RISK_WORKFLOW.md](README_RISK_WORKFLOW.md).

### Prerequisites

**Input Requirements:**
- Cause & Risk dataset with multiple model analyses (`.cause_risk.*.json` files)
- Correlated final dataset (from `correlate_risks.py`)
- Judge model access (GPT-4o recommended for evaluation quality)

**Environment:**
- `OPENAI_API_KEY` set for judge model
- Python packages: `openai`, `python-dotenv`

### Quick Start

```bash
# Automated workflow
./run_evaluation_risk.sh

# OR manual steps
python3 datasets/create_risk_sample.py
python3 evaluate_risk.py
python3 analyze_results.py --results results/risk_results.json --summary results/risk_summary.md --csv results/risk_data.csv
python3 generate_dashboard.py --results results/risk_results.json --output results/risk_dashboard.html
```

### Evaluation Components

**Script: `evaluate_risk.py`**
- Reads correlated dataset with `cause_analysis` and `risk_assessment` fields
- Extracts analyses from different models (GPT-4o, GPT-4o-mini, Qwen, etc.)
- Queries judge model to score each analysis on 5 criteria
- Outputs structured JSON with scores and justifications

**Script: `analyze_results.py`**
- Aggregates scores across models and criteria
- Generates statistical summaries (mean, median, std dev)
- Creates markdown report with model comparison tables
- Supports both summarization and risk evaluation results

**Script: `generate_dashboard.py`**
- Creates interactive HTML dashboard
- Visualizes score distributions per model and criterion
- Side-by-side comparisons of model outputs
- Incident-level detail views with full evidence

### Judge Criteria (Security Risk Analyst Perspective)

The judge model evaluates each analysis on **5 criteria** (1-5 scale):

1. **Cause Identification Accuracy** (1-5)
   - Correctly categorizes as Malicious / Legitimate / Misconfiguration
   - Identifies specific attack techniques or benign operational causes
   - Distinguishes between intentional malicious activity and system misconfigurations

2. **Evidence-Based Reasoning** (1-5)
   - Analysis grounded in actual events from DAG evidence
   - Logical connection between observed behavior and proposed causes
   - Avoids speculation unsupported by evidence

3. **Risk Level Accuracy** (1-5)
   - Appropriate risk classification (Critical / High / Medium / Low)
   - Risk level justified by actual threat severity
   - Considers both likelihood and impact

4. **Business Impact Assessment** (1-5)
   - Realistic evaluation of potential business consequences
   - Specific impact types (data breach, service disruption, compliance violation)
   - Appropriate scope and severity of impact description

5. **Investigation Priority** (1-5)
   - Actionable prioritization (Immediate / High / Medium / Low)
   - Aligned with risk level and business impact
   - Clear guidance for security team response

**Scoring Guidelines:**
- **5**: Excellent - Highly accurate, well-justified, actionable
- **4**: Good - Mostly accurate with minor issues
- **3**: Adequate - Correct direction but lacks depth or has some inaccuracies
- **2**: Poor - Significant errors or missing key elements
- **1**: Unacceptable - Fundamentally incorrect or irrelevant

### Cost Estimates

**Evaluation Costs (GPT-4o judge):**
- 50 incidents × 4 models = 200 evaluations
- ~2,000 tokens per evaluation (input + output)
- Total: ~400,000 tokens ≈ $5 USD
- Time: ~30-45 minutes

**Model Comparison:**
- GPT-4o: $5.00 / 1M input tokens, $15.00 / 1M output tokens
- GPT-4o-mini: $0.15 / 1M input, $0.60 / 1M output (cheaper but less reliable as judge)

### Example Output

**Risk Evaluation Results (`results/risk_results.json`):**
```json
{
  "incident_id": "abc123...",
  "category": "Malware",
  "model_evaluations": {
    "cause_risk_gpt4o_mini": {
      "cause_identification": {"score": 4, "justification": "..."},
      "evidence_reasoning": {"score": 5, "justification": "..."},
      "risk_level": {"score": 4, "justification": "..."},
      "business_impact": {"score": 3, "justification": "..."},
      "investigation_priority": {"score": 4, "justification": "..."},
      "average_score": 4.0
    }
  }
}
```

**Summary Report (`results/risk_summary.md`):**
```
Model Performance Summary
=========================

cause_risk_gpt4o:        4.2 ± 0.6
cause_risk_gpt4o_mini:   3.8 ± 0.7
cause_risk_qwen2_5:      3.5 ± 0.8

Criterion Breakdown:
- Cause Identification:     3.9
- Evidence Reasoning:       4.1
- Risk Level Accuracy:      3.7
- Business Impact:          3.6
- Investigation Priority:   3.8
```

### Workflow Integration

**Generate → Evaluate → Iterate:**

```bash
# 1. Generate Cause & Risk dataset (see README_RISK_WORKFLOW.md)
./generate_cause_risk_analysis.sh datasets/my_dataset.jsonl --model gpt-4o-mini --group-events
python3 correlate_risks.py datasets/my_dataset.*.json -o final_dataset.json

# 2. Sample for evaluation
python3 datasets/create_risk_sample.py

# 3. Evaluate
python3 evaluate_risk.py datasets/risk_sample.json -o results/risk_results.json

# 4. Analyze results
python3 analyze_results.py -r results/risk_results.json -s results/risk_summary.md

# 5. View dashboard
python3 generate_dashboard.py -r results/risk_results.json -s datasets/risk_sample.json -o results/risk_dashboard.html
open results/risk_dashboard.html
```

### Tips & Best Practices

**Sampling Strategy:**
- Include diverse incident types (Normal + Malware)
- Sample across complexity levels (event count variation)
- Use stratified sampling to ensure representative coverage

**Judge Model Selection:**
- **GPT-4o**: Best evaluation quality, use for final results
- **GPT-4o-mini**: Faster/cheaper for development iteration
- Avoid using same model as judge and generator (evaluation bias)

**Interpreting Results:**
- Scores < 3.0: Significant improvement needed
- Scores 3.0-4.0: Acceptable, room for refinement
- Scores > 4.0: High quality analysis
- High variance: Inconsistent performance across incidents

**Common Issues:**
- Low "Evidence Reasoning": Model hallucinating causes not in DAG
- Low "Risk Level": Overestimating or underestimating severity
- Low "Business Impact": Generic impacts instead of specific consequences
