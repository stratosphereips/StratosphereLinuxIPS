# Dataset Generation Pipeline for Slips Alert Analysis

## 1. Overview

This pipeline transforms raw Slips security logs into structured multi-model analysis datasets. The workflow consists of four stages: (1) sampling incidents from raw logs into JSONL format, (2) generating DAG-based structural analysis, (3) producing LLM-enhanced summaries with behavior analysis from multiple models, and (4) correlating all analyses into a unified JSON dataset. The output provides comprehensive incident analysis from different analytical perspectives, enabling comparative evaluation of model performance on security analysis tasks.

## 2. Pipeline Components

### 2.1 Python Scripts

**`sample_dataset.py`**
Samples INCIDENT alerts and their associated EVENT alerts from Slips `alerts.json` files. Preserves the complete event context for each incident by following CorrelID references. Supports filtering by category (normal/malware), severity (low/medium/high), and reproducible sampling via random seeds. Outputs JSONL format compatible with downstream analysis tools.

**`alert_dag_parser.py`**
Parses JSONL incident files and generates Directed Acyclic Graph (DAG) analysis showing the chronological structure of security events. Extracts incident metadata (source IPs, timewindows, threat levels, timelines) and produces comprehensive event summaries. Outputs structured JSON with incident-level analysis.

**`alert_dag_parser_llm.py`**
Generates LLM-enhanced analysis by querying language models with structured incident data. Implements two key optimizations: (1) event grouping by pattern normalization (replaces IPs, ports, numbers with placeholders to identify identical patterns), reducing token counts by 96-99% for large incidents, and (2) dual-prompt analysis generating both severity-assessed summaries and structured behavior explanations. Supports multiple LLM backends via OpenAI-compatible APIs. Outputs JSON with both `summary` and `behavior_analysis` fields.

**`correlate_incidents.py`**
Merges multiple JSON analysis files by matching `incident_id` fields. Combines DAG analysis with multiple LLM analyses (from different models) into a single unified dataset. Automatically detects analysis types from filenames (e.g., `.dag.json`, `.llm.gpt-4o-mini.json`, `.llm.qwen2.5.json`) and creates appropriately named fields in the output. Produces consolidated JSON suitable for model comparison and evaluation.

**`merge_datasets.py`**
Merges multiple correlated dataset JSON files into a single unified dataset. Removes duplicates based on `incident_id` while preserving all analysis fields from each incident. Useful for extending existing datasets by combining separately generated correlated datasets. Supports multiple input files, automatic deduplication, and optional compact output format.

### 2.2 Shell Wrappers

**`sample_dataset.sh`**
Wrapper for `sample_dataset.py` providing simplified command-line interface. Handles argument parsing, validation, and automatic file naming (appends `.jsonl` extension). Supports filtering options, random seed configuration, and optional statistics generation.

**`generate_dag_analysis.sh`**
Wrapper for `alert_dag_parser.py` with automatic output filename generation based on input JSONL file. Converts `input.jsonl` to `input.dag.json` by default. Provides colored status logging and error handling.

**`generate_llm_analysis.sh`**
Wrapper for `alert_dag_parser_llm.py` supporting multiple model configurations. Auto-generates output filenames incorporating model names (e.g., `input.llm.gpt-4o-mini.json`, `input.llm.qwen2.5.json`). Handles model endpoint configuration for both cloud APIs (OpenAI) and local servers (Ollama). Passes through optimization flags for event grouping and behavior analysis.

## 3. Dataset Generation Workflow

### 3.1 Prerequisites

**Input Requirements:**
- Raw Slips logs: `alerts.json` files from Slips network security analysis
- Directory structure: `sample_logs/alya_datasets/{Normal,Malware}/...`

**Model Configuration:**
- **GPT-4o-mini**: OpenAI API key in environment variable `OPENAI_API_KEY`
- **Qwen2.5:3b**: Ollama server running at `http://10.147.20.102:11434/v1` (adjust as needed)
- **Qwen2.5:1.5b**: Ollama server with model installed

**Software Dependencies:**
- Python 3.6+ with standard library only (no external packages required)
- `bash`, `jq` for shell scripts
- OpenAI Python package for LLM analysis: `pip install openai`

### 3.2 Step-by-Step Process

**Step 1: Sample Incidents from Raw Logs**

Generate a JSONL file containing sampled incidents with all associated events:

```bash
./sample_dataset.sh 20 my_dataset --category malware --seed 42 --include-stats
```

This creates:
- `my_dataset.jsonl` - Sampled incidents and events in JSONL format
- `my_dataset.stats.json` - Statistics about the sample (optional)

**Step 2: Generate DAG Analysis**

Parse the JSONL file and generate structural DAG analysis:

```bash
./generate_dag_analysis.sh my_dataset.jsonl
```

Output: `my_dataset.dag.json` - JSON array of incidents with DAG-based analysis

**Step 3: Generate LLM Analysis (GPT-4o-mini)**

Query GPT-4o-mini for enhanced analysis with event grouping and behavior analysis:

```bash
./generate_llm_analysis.sh my_dataset.jsonl \
  --model gpt-4o-mini \
  --base-url https://api.openai.com/v1 \
  --group-events \
  --behavior-analysis
```

Output: `my_dataset.llm.gpt-4o-mini.json` - JSON array with `summary` and `behavior_analysis` fields

**Step 4: Generate LLM Analysis (Qwen2.5:3b)**

Query Qwen2.5:3b model via Ollama with same optimization flags:

```bash
./generate_llm_analysis.sh my_dataset.jsonl \
  --model qwen2.5:3b \
  --base-url http://10.147.20.102:11434/v1 \
  --group-events \
  --behavior-analysis
```

Output: `my_dataset.llm.qwen2.5.json` - JSON array with model-specific analysis

**Step 5: Generate LLM Analysis (Qwen2.5:1.5b)**

Query Qwen2.5:1.5b model for comparison with smaller model:

```bash
./generate_llm_analysis.sh my_dataset.jsonl \
  --model qwen2.5:1.5b \
  --base-url http://10.147.20.102:11434/v1 \
  --group-events \
  --behavior-analysis
```

Output: `my_dataset.llm.qwen2.5.1.5b.json` - JSON array from smaller model

**Step 6: Correlate All Analyses**

Merge all analysis files into a unified dataset by incident_id, including category information from the original JSONL:

```bash
python3 correlate_incidents.py my_dataset.*.json --jsonl my_dataset.jsonl -o final_dataset.json
```

Output: `final_dataset.json` - Consolidated dataset with all analyses per incident

**Note:** The `--jsonl` parameter is used to extract the category field (Malware/Normal) from the original sampled data, ensuring proper ground truth labeling in the final dataset.

### 3.3 Complete Workflow Example

```bash
# Full pipeline execution
./sample_dataset.sh 20 my_dataset --category malware --seed 42
./generate_dag_analysis.sh my_dataset.jsonl
./generate_llm_analysis.sh my_dataset.jsonl --model gpt-4o-mini --group-events --behavior-analysis
./generate_llm_analysis.sh my_dataset.jsonl --model qwen2.5:3b --base-url http://10.147.20.102:11434/v1 --group-events --behavior-analysis
./generate_llm_analysis.sh my_dataset.jsonl --model qwen2.5:1.5b --base-url http://10.147.20.102:11434/v1 --group-events --behavior-analysis
python3 correlate_incidents.py my_dataset.*.json --jsonl my_dataset.jsonl -o final_dataset.json
```

Files generated:
- `my_dataset.jsonl` - Sampled incidents (JSONL)
- `my_dataset.dag.json` - DAG analysis
- `my_dataset.llm.gpt-4o-mini.json` - GPT-4o-mini analysis
- `my_dataset.llm.qwen2.5.json` - Qwen2.5:3b analysis
- `my_dataset.llm.qwen2.5.1.5b.json` - Qwen2.5:1.5b analysis
- `final_dataset.json` - Unified correlated dataset

### 3.4 Extending Existing Datasets

To add more incidents to an existing correlated dataset without regenerating from scratch:

**Step 1: Sample Additional Incidents**

Use a different random seed to ensure new samples don't duplicate existing ones:

```bash
./sample_dataset.sh 20 extension --category malware --seed 99
```

**Step 2: Generate All Analyses for Extension**

Run the full analysis pipeline on the new samples:

```bash
./generate_dag_analysis.sh extension.jsonl
./generate_llm_analysis.sh extension.jsonl --model gpt-4o-mini --group-events --behavior-analysis
./generate_llm_analysis.sh extension.jsonl --model qwen2.5:3b --base-url http://10.147.20.102:11434/v1 --group-events --behavior-analysis
./generate_llm_analysis.sh extension.jsonl --model qwen2.5:1.5b --base-url http://10.147.20.102:11434/v1 --group-events --behavior-analysis
```

**Step 3: Correlate Extension Data**

```bash
python3 correlate_incidents.py extension.*.json --jsonl extension.jsonl -o extension_dataset.json
```

**Step 4: Merge with Existing Dataset**

Combine the original and extension datasets, automatically removing any duplicates:

```bash
python3 merge_datasets.py final_dataset.json extension_dataset.json -o final_dataset_v2.json
```

**Alternative: Merge Multiple Extensions**

If you have multiple extension datasets:

```bash
python3 merge_datasets.py final_dataset.json extension1_dataset.json extension2_dataset.json -o combined_dataset.json
```

**Note on Deduplication:** The `merge_datasets.py` script automatically detects and removes duplicate incidents based on `incident_id`. If the same incident appears in multiple input files, only the first occurrence is kept.

**Verification:** After merging, verify the operation completed successfully:

```bash
python3 verify_merge.py --verbose
```

This validates file integrity, count accuracy, deduplication correctness, completeness, and data integrity. Use `--inputs` and `--output` flags to verify custom merge operations.

## 4. Output Dataset Structure

The final correlated dataset is a JSON array where each object represents one incident with all analyses:

```json
[
  {
    "incident_id": "bd47e95b-a211-41b1-9644-40d6a2e77a07",
    "category": "Malware",
    "source_ip": "10.0.2.15",
    "timewindow": "12",
    "timeline": "2024-04-05 16:53:07 to 16:53:50",
    "threat_level": 15.36,
    "event_count": 4604,
    "dag_analysis": "Comprehensive analysis:\n- Source IP: 10.0.2.15\n- Timewindow: 12...",
    "llm_gpt4o_mini_analysis": {
      "summary": "Incident bd47e95b-a211-41b1-9644-40d6a2e77a07 involves...",
      "behavior_analysis": "**Source:** 10.0.2.15\n**Activity:** Port scanning...\n**Detected Flows:**\n• 10.0.2.15 → 185.29.135.234:443/TCP (HTTPS)\n..."
    },
    "llm_qwen2_5_3b_analysis": {
      "summary": "This incident represents a sophisticated attack...",
      "behavior_analysis": "**Source:** 10.0.2.15\n**Activity:** Multi-stage attack...\n..."
    },
    "llm_qwen2_5_1_5b_analysis": {
      "summary": "The incident shows malicious behavior with...",
      "behavior_analysis": "**Source:** 10.0.2.15\n**Activity:** Network reconnaissance...\n..."
    }
  }
]
```

**Key Fields:**
- `incident_id`: UUID identifying the unique security incident
- `category`: Classification of the capture origin ("Malware" or "Normal")
- `source_ip`: Primary source IP address for the incident
- `timewindow`: Slips timewindow number for temporal context
- `timeline`: Human-readable time range (start to end)
- `threat_level`: Accumulated threat score from Slips
- `event_count`: Number of security events in this incident
- `dag_analysis`: Structural DAG-based analysis (string)
- `llm_<model>_analysis`: Object with `summary` and `behavior_analysis` strings

**Analysis Field Contents:**

*DAG Analysis:* Chronological event summary with threat levels, detection types, and temporal patterns.

*LLM Summary:* Severity-assessed event descriptions prioritizing high-confidence and high-threat-level evidence. Groups similar events by pattern to reduce verbosity.

*LLM Behavior Analysis:* Structured technical explanation formatted as:
```
**Source:** <IP>
**Activity:** <brief activity type>
**Detected Flows:**
• <src:port/proto> → <dest> (service)
• [additional flows]

**Summary:** [1-2 sentence technical summary]
```

## 5. Performance Considerations

### Event Grouping (--group-events)

**Purpose:** Reduce token count for large incidents to enable processing on low-specification devices.

**Mechanism:** Normalizes event descriptions by replacing variable components (IP addresses → `<IP>`, ports → `<PORT>`, numbers → `<NUM>`) to identify identical patterns. Groups events with matching normalized patterns while preserving threat level and timing information.

**Impact:**
- Small incident (103 events): 3,522 tokens → 976 tokens (72% reduction)
- Large incident (4,604 events): ~50,000 tokens → 1,897 tokens (96% reduction)

**Trade-off:** Slight reduction in granularity (individual IPs/ports shown as samples) for massive token savings. Recommended for all production use.

### Behavior Analysis (--behavior-analysis)

**Purpose:** Generate structured technical explanations of network behavior alongside severity-assessed summaries.

**Mechanism:** Issues two separate LLM queries per incident:
1. Summary prompt: Assesses severity and filters high-priority evidence
2. Behavior prompt: Produces structured flow analysis and technical summary

**Impact:**
- Adds ~1,500 tokens per incident (behavior prompt)
- Doubles API calls and processing time per incident
- Provides richer analytical context for security analysts

**Trade-off:** Enhanced analysis quality and readability at cost of increased processing time and API usage. Recommended for datasets under 100 incidents or when quality is prioritized over speed.

### Combined Usage

Using both flags together (`--group-events --behavior-analysis`) achieves optimal balance:
- Event grouping minimizes prompt size (token reduction)
- Behavior analysis maximizes output quality (richer insights)
- Large incidents become processable while maintaining analytical depth

**Example token counts with both flags:**
- 4,604 events: 1,897 tokens (summary) + 1,527 tokens (behavior) = 3,424 total tokens
- Processing time: ~10-15 seconds per incident on low-spec devices (Ollama on Raspberry Pi)

---

**Pipeline Maintained By:** Security Analysis Team
**Last Updated:** 2025-10-13
**Version:** 2.0 (JSON-based workflow with event grouping and behavior analysis)
