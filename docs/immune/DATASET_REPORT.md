# Network Event Summarization Dataset for Slips IDS

## Table of Contents

- [1. Task description](#1-task-description)
- [2. Limitations](#2-limitations)
  - [Hardware Constraints](#hardware-constraints)
  - [Scope Constraints](#scope-constraints)
- [3. Dataset Generation Workflow](#3-dataset-generation-workflow)
  - [Stage 1: Incident Sampling](#stage-1-incident-sampling)
  - [Stage 2: Structural Analysis](#stage-2-structural-analysis)
  - [Stage 3: Multi-Model LLM Analysis](#stage-3-multi-model-llm-analysis)
  - [Stage 4: Dataset Correlation](#stage-4-dataset-correlation)
  - [Dataset Extension](#dataset-extension)
  - [Workflow Diagram](#workflow-diagram)
  - [Event Grouping Strategy](#event-grouping-strategy)
  - [Additional Optimizations](#additional-optimizations)
  - [Dataset Structure](#dataset-structure)

## 1. Task description 

Develop a dataset for network security event summarization to be integrated with the Slips Immune system, optimized for deployment on low-resource hardware such as the Raspberry Pi 5. This dataset will be used to fine-tune compact language models capable of generating concise and actionable summaries of security incidents from raw Slips alert data, enabling real-time threat analysis in resource-constrained environments.

## 2. Limitations

### Hardware Constraints
- **Platform**: Raspberry Pi 5 with limited RAM and processing power
- **Model Size**: Only small language models (1.5B-3B parameters) are viable on target hardware
- **Real-time Processing**: Target 10-15 seconds per incident on RPi5 with Ollama requires aggressive token optimization

### Scope Constraints
- **Alert Format**: Analysis currently limited to Slips alert format; generalization to other IDS outputs requires format adaptation
- **Token Budget**: Input and output tokens must be minimized to enable real-time inference on resource-constrained hardware (~2000 tokens max)
- **Output Constraints**: Summaries must be concise (150-300 tokens) while maintaining security context

## 3. Dataset Generation Workflow

The dataset generation process consists of four stages, each implemented as Python scripts with shell wrappers that simplify execution, handle argument validation, and automate file naming. This modular design enables flexible experimentation with different models and configurations while maintaining reproducibility.

**Detailed documentation**: See [README_dataset_summary_workflow.md](README_dataset_summary_workflow.md) for complete pipeline specifications and advanced usage.

### Stage 1: Incident Sampling
Extract security incidents from Slips `alerts.json` logs with category labels (Malware/Normal):

```bash
./sample_dataset.sh 20 my_dataset --category malware --seed 42
```

**Output**: `my_dataset.jsonl` (JSONL format with incidents and events)

### Stage 2: Structural Analysis
Generate DAG-based chronological analysis of incident events:

```bash
./generate_dag_analysis.sh my_dataset.jsonl
```

**Output**: `my_dataset.dag.json` (incident metadata + event timeline)

### Stage 3: Multi-Model LLM Analysis
Query multiple language models with optimized prompts:

```bash
# GPT-4o-mini (baseline)
./generate_llm_analysis.sh my_dataset.jsonl --model gpt-4o-mini \
  --group-events --behavior-analysis

# Qwen2.5:3b (target model)
./generate_llm_analysis.sh my_dataset.jsonl --model qwen2.5:3b \
  --base-url http://10.147.20.102:11434/v1 --group-events --behavior-analysis

# Qwen2.5:1.5b (minimal model)
./generate_llm_analysis.sh my_dataset.jsonl --model qwen2.5:1.5b \
  --base-url http://10.147.20.102:11434/v1 --group-events --behavior-analysis
```

**Outputs**: Model-specific JSON files with `summary` and `behavior_analysis` fields

### Stage 4: Dataset Correlation
Merge all analyses into unified dataset by incident ID:

```bash
python3 correlate_incidents.py my_dataset.*.json \
  --jsonl my_dataset.jsonl -o final_dataset.json
```

**Output**: `final_dataset.json` (consolidated dataset with all analyses)

### Dataset Extension

To expand existing datasets without regeneration, use `merge_datasets.py` to combine multiple correlated datasets with automatic deduplication:

```bash
# Generate new samples with different seed
./sample_dataset.sh 20 extension --category malware --seed 99

# Run full analysis pipeline on extension
./generate_dag_analysis.sh extension.jsonl
./generate_llm_analysis.sh extension.jsonl --model qwen2.5:3b --group-events --behavior-analysis

# Correlate extension data
python3 correlate_incidents.py extension.*.json --jsonl extension.jsonl -o extension_dataset.json

# Merge with existing dataset (removes duplicates by incident_id)
python3 merge_datasets.py final_dataset.json extension_dataset.json -o final_dataset_v2.json
```

This approach enables incremental dataset growth while maintaining consistency across all analysis fields.

### Workflow Diagram

```
Raw Slips Logs (alerts.json)
         ↓
[sample_dataset.py] → incidents.jsonl
         ↓
         ├─→ [alert_dag_parser.py] → incidents.dag.json
         ├─→ [alert_dag_parser_llm.py + GPT-4o-mini] → incidents.llm.gpt-4o-mini.json
         ├─→ [alert_dag_parser_llm.py + Qwen2.5:3b] → incidents.llm.qwen2.5.json
         └─→ [alert_dag_parser_llm.py + Qwen2.5:1.5b] → incidents.llm.qwen2.5.1.5b.json
         ↓
[correlate_incidents.py] → final_dataset.json
```

### Event Grouping Strategy

The `--group-events` optimization reduces token count through pattern normalization:

1. **Pattern Normalization**: Replaces variable components in event descriptions with placeholders
   - IPv4 addresses → `<IP>`
   - Port numbers → `<PORT>` (handles formats: `443/TCP`, `port: 80`)
   - Standalone numbers → `<NUM>`

2. **Pattern-Based Grouping**: Groups events with identical normalized patterns
   - Example: "Connection to 192.168.1.5:443" + "Connection to 10.0.2.15:443" → single pattern "Connection to `<IP>`:`<PORT>`"
   - Preserves count, time range, and sample values (first 5 unique IPs/ports) per group

3. **Token Reduction**:
   - 103 events: 3,522 → 976 tokens (72% reduction)
   - 4,604 events: ~50,000 → 1,897 tokens (96% reduction)

4. **Information Loss Analysis**:
   - **Lost**: Individual timestamps (only ranges), complete IP/port lists (max 5 samples), exact event sequence, duplicate frequency tracking
   - **Retained**: Semantic patterns, event counts, representative samples, temporal context, protocol details, attack patterns
   - **Impact**: Small incidents (~28% loss), large incidents (~90-95% loss, mostly repetitive data)
   - **Justification**: Enables LLM summarization on RPi5; alternative is inability to process large incidents

### Additional Optimizations

**Dual-Prompt Analysis** (`--behavior-analysis`): Generates both severity-filtered summaries and structured technical flow analysis, providing richer training signals for model fine-tuning.

**Severity Filtering Strategy**: The dual-prompt approach implements intelligent filtering to manage token budgets:
- Prioritizes high-threat evidence in summaries for focused incident assessment
- May omit low-confidence events to reduce token consumption
- Balanced by generating both severity-filtered summaries and comprehensive behavior analysis
- Trade-off: Enables complete incident coverage while maintaining concise outputs suitable for resource-constrained deployment

**Multi-Model Evaluation**: Compares GPT-4o (quality baseline), GPT-4o-mini,  Qwen2.5:3b (target deployment), and Qwen2.5:1.5b (minimal viable model) to assess performance-resource trade-offs.

### Dataset Structure

Each incident in the final dataset contains:
- **Metadata**: incident_id, category, source_ip, timewindow, threat_level
- **DAG Analysis**: Chronological event timeline with threat scores
- **LLM Summaries**: Model-specific severity assessments
- **Behavior Analysis**: Structured network flow descriptions

Token efficiency enables deployment on Raspberry Pi 5 while maintaining security analysis quality suitable for real-time intrusion detection.
