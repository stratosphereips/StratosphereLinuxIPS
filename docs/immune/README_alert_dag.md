# Alert DAG Parser

## Overview

`alert_dag_parser.py` is a Python tool that parses JSONL (JSON Lines) files containing Slips security incidents and events in IDEA format. Unlike traditional log parsers that rely on regex pattern matching of text descriptions, this tool uses **structured JSON field-based classification** to ensure compatibility with current and future unknown alert types.

## Design Philosophy

### Future-Proof Architecture

The tool is designed to handle new alert types without code modifications by:

1. **Field-based classification** - Uses standardized JSON fields (`Severity`, `Source`, `Target`) instead of parsing description text
2. **Graceful degradation** - Unknown patterns are grouped and displayed automatically
3. **No regex maintenance** - New alert types work immediately without updating pattern definitions

### Why Not Text Parsing?

Traditional approaches like `slips_dag_generator.py` use regex patterns on description text:
```python
# Brittle approach - breaks when text changes
r'horizontal port scan to port\s+(\d+/\w+)'
r'C&C channel.*?destination IP: ([\d.]+)'
```

**Problems:**
- Breaks when description text changes
- Requires code updates for new alert types
- Fragile maintenance burden

**Solution:**
```python
# Robust approach - uses structured fields
severity = event['Severity']
target_ip = event['Target'][0]['IP']
target_port = event['Target'][0]['Port'][0]
```

## File Format

### JSONL Structure

The input file contains one JSON object per line with two entry types:

#### Incidents (Alerts)
```json
{
  "Status": "Incident",
  "ID": "96b2b890-8e6d-458a-9217-71cfff0ef1c5",
  "Source": [{"IP": "192.168.1.122"}],
  "StartTime": "1970-01-01T00:00:13.676697+00:00",
  "CreateTime": "2025-03-06T13:53:53.687361+00:00",
  "CorrelID": ["event-uuid-1", "event-uuid-2", ...],
  "Note": "{\"accumulated_threat_level\": 15.36, \"timewindow\": 1, \"EndTime\": \"...\"}"
}
```

#### Events (Evidence)
```json
{
  "Status": "Event",
  "ID": "9180df3e-449d-412b-b8c9-45fb76831e12",
  "Severity": "Info",
  "StartTime": "1970-01-01T00:00:13.676697+00:00",
  "Confidence": 1.0,
  "Description": "Connecting to private IP: fd2d:ab8c:225::1 on destination port: 53 threat level: info.",
  "Source": [{"IP": "fd2d:ab8c:225:0:f575:44d7:5a0b:2224", "Port": [49885]}],
  "Target": [{"IP": "fd2d:ab8c:225::1", "Port": [53]}],
  "Note": "{\"uids\": [...], \"threat_level\": \"info\", \"timewindow\": 1}"
}
```

### Correlation Model

- Incidents contain `CorrelID` array with Event UUIDs
- Events are linked to Incidents via their `ID` field
- One Incident can have multiple Events
- Events can theoretically belong to multiple Incidents

## Usage

### Basic Usage

```bash
# Analyze all incidents in the file
python3 alert_dag_parser.py alerts.json

# Analyze specific incident by UUID
python3 alert_dag_parser.py alerts.json --incident-id 96b2b890-8e6d-458a-9217-71cfff0ef1c5

# Save output to file
python3 alert_dag_parser.py alerts.json -o incident_report.txt

# Verbose mode (shows parsing progress)
python3 alert_dag_parser.py alerts.json --verbose
```

### Command-Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--incident-id` | `-i` | Analyze specific incident by UUID |
| `--output` | `-o` | Write output to file instead of stdout |
| `--verbose` | `-v` | Show parsing progress and statistics |

### Example Workflow

```bash
# 1. Quick analysis of all incidents
./alert_dag_parser.py sample_logs/alya_datasets/Malware/.../alerts.json

# 2. Identify interesting incident from summary
# 3. Deep dive into specific incident
./alert_dag_parser.py alerts.json -i <UUID> -o incident_analysis.txt

# 4. Review detailed report
less incident_analysis.txt
```

## Output Format

### Comprehensive Analysis

The tool generates a comprehensive per-incident analysis showing ALL associated events:

```
============================================================
Incident: 96b2b890-8e6d-458a-9217-71cfff0ef1c5
Source IP: 192.168.1.122 | Timewindow: 1
Timeline: 1970-01-01 00:00:13 to 1970-01-01 01:00:13
Threat Level: 15.36 | Events: 24

• 00:00-00:20 - 6 events to 224.0.0.1 [HIGH]
  - Connection on port 0 from 0.0.0.0:0 to 224.0.0.1:0. threat level: high. (x6)

• 00:05-00:15 - 8 events to port 53 [INFO]
  - Connecting to private IP: fd2d:ab8c:225::1 on destination port: 53 threat level: info. (x4)
  - Connecting to private IP: 192.168.1.1 on destination port: 53 threat level: info. (x4)

• 00:10 - 3 events to 81.169.128.232:4743 [MEDIUM]
  - Connection to unknown destination port 4743/TCP destination IP 81.169.128.232. threat level: medium. (x3)

• 00:12 - 1 events to 176.9.116.3:3889 [HIGH]
  - Connection to unknown destination port 3889/TCP destination IP 176.9.116.3. threat level: high.

• 00:07-00:13 - 6 events to 4 IPs [INFO]
  - A connection without DNS resolution to IP: 81.169.128.232 threat level: info. (x3)
  - A connection without DNS resolution to IP: 176.9.116.3 threat level: info.
  - A connection without DNS resolution to IP: 107.170.231.118 threat level: info.
  - A connection without DNS resolution to IP: 37.187.54.76 threat level: info.

Total Evidence: 24 events
Severity breakdown: High: 7, Medium: 3, Info: 14
```

### Output Structure

Each incident analysis includes:

1. **Header** - Incident UUID and metadata
2. **Timeline** - Start and end times from timewindow
3. **Threat metrics** - Accumulated threat level and event count
4. **Grouped events** - Events grouped by:
   - Severity level (Critical → High → Medium → Low → Info)
   - Target characteristics (IP, port, or pattern)
   - Time range (earliest to latest in group)
5. **Event details** - Up to 3 example descriptions per group with counts
6. **Summary statistics** - Total events and severity breakdown

### Grouping Logic

Events are grouped using structured fields:

```python
group_key = (event.severity, target_summary)

# target_summary examples:
# - "192.168.1.1:53" (specific IP and port)
# - "224.0.0.1" (IP only)
# - "port 53" (port only)
# - "4 IPs" (multiple targets)
# - "Unknown" (no target info)
```

This ensures consistent grouping regardless of description text variations.

## Technical Architecture

### Core Classes

#### `JSONEvent`
Dataclass representing individual security events (evidence).

**Key Fields:**
- `id` - Unique event identifier (UUID)
- `severity` - Info, Low, Medium, High, Critical
- `source_ips` - List of source IP addresses
- `source_ports` - List of source ports
- `target_ips` - List of destination IP addresses
- `target_ports` - List of destination ports
- `description` - Human-readable text (display only)
- `confidence` - Numeric confidence score
- `note` - Parsed metadata dictionary

**Design Note:** Uses lists for IPs/ports to handle multi-target events gracefully.

#### `JSONIncident`
Dataclass representing security incidents (alerts).

**Key Fields:**
- `id` - Unique incident identifier (UUID)
- `source_ips` - List of source IPs involved in incident
- `correl_ids` - List of Event UUIDs associated with this incident
- `note` - Metadata including `accumulated_threat_level`, `timewindow`, `EndTime`

#### `AlertJSONParser`
Parses JSONL files and builds incident-event correlation.

**Responsibilities:**
- Line-by-line JSONL parsing
- Separation of Incidents from Events
- Event lookup index creation (`{event_id: event_object}`)
- Error handling and validation

#### `AlertDAGGenerator`
Generates comprehensive analysis output.

**Responsibilities:**
- Field-based event grouping (not text parsing)
- Severity-based prioritization
- Timeline formatting
- Summary statistics generation

### Data Flow

```
JSONL File
    ↓
AlertJSONParser.parse_file()
    ├─→ List[JSONIncident]
    └─→ Dict[event_id: JSONEvent]
    ↓
For each Incident:
    AlertJSONParser.get_incident_events()
        ↓
    List[JSONEvent] (correlated events)
        ↓
    AlertDAGGenerator.generate_comprehensive_analysis()
        ├─→ Group by (severity, target_summary)
        ├─→ Sort by severity priority
        ├─→ Format timeline and descriptions
        └─→ Generate statistics
    ↓
Comprehensive Analysis Output
```

### Field-Based Classification

Unlike regex-based parsers, this tool classifies events using structured fields:

```python
def _create_target_summary(self, event: JSONEvent) -> str:
    """Create target summary using structured fields."""
    if event.target_ips and event.target_ports:
        # Both IP and port available
        ip_summary = event.target_ips[0] if len(event.target_ips) == 1 else f"{len(event.target_ips)} IPs"
        port_summary = str(event.target_ports[0]) if len(event.target_ports) == 1 else f"{len(event.target_ports)} ports"
        return f"{ip_summary}:{port_summary}"
    elif event.target_ips:
        # Only IP available
        return event.target_ips[0] if len(event.target_ips) == 1 else f"{len(event.target_ips)} IPs"
    elif event.target_ports:
        # Only port available
        return f"port {event.target_ports[0]}" if len(event.target_ports) == 1 else f"{len(event.target_ports)} ports"
    else:
        # No structured target info - use description prefix as fallback
        desc_prefix = event.description.split()[0] if event.description else "Unknown"
        return desc_prefix
```

**Benefits:**
- Works with any event type (current or future)
- No regex pattern maintenance
- Consistent grouping logic
- Graceful fallback for edge cases

## Example Datasets

### Test Dataset Structure

```
sample_logs/alya_datasets/Malware/
├── CTU-Malware-Capture-Botnet-219-2/
├── CTU-Malware-Capture-Botnet-327-2/
└── CTU-Malware-Capture-Botnet-346-1/
    └── 2018-04-03_win12-fixed/
        └── 9/
            ├── alerts.json  (3,226 entries: 47 incidents, 3,179 events)
            └── slips.log    (Original Slips log output)
```

### Dataset Characteristics

**CTU-Malware-Capture-Botnet-346-1 (9):**
- 47 Incidents
- 3,179 Events
- Event types:
  - Private IP connections
  - Port 0 connections (multicast)
  - Unknown destination ports
  - DNS resolution issues
  - Reconnection attempts
  - Long connections

### Sample Analysis

```bash
# Quick stats
python3 alert_dag_parser.py sample_logs/alya_datasets/Malware/CTU-Malware-Capture-Botnet-346-1/2018-04-03_win12-fixed/9/alerts.json --verbose 2>&1 | head -3

# Output:
# Parsing file: sample_logs/alya_datasets/Malware/...
# Found 47 incidents and 3179 events
```

## Error Handling

### Graceful Error Recovery

The parser handles common issues without crashing:

1. **Malformed JSON lines** - Skipped with warning
2. **Missing Event IDs** - Warning logged, analysis continues
3. **Missing fields** - Defaults to "Unknown" or empty lists
4. **Invalid timestamps** - Falls back to raw ISO string
5. **Unparseable Note fields** - Stored as raw string

### Warning Messages

```
Warning: JSON parse error at line 42: Expecting ',' delimiter
Warning: Event abc123-... not found for Incident xyz789-...
Warning: Unknown status 'Test' at line 156
```

### Exit Codes

- `0` - Success
- `1` - File not found, write error, or no incidents found

## Performance Considerations

### Memory Usage

- **Efficient**: All events and incidents loaded into memory
- **Typical**: ~50 incidents + ~3,000 events = ~5-10 MB RAM
- **Large datasets**: May need streaming for >100,000 events

### Processing Speed

- ~3,000 events parsed in <1 second
- JSON parsing is the bottleneck (not analysis logic)
- Linear time complexity: O(incidents + events)

### Scalability Tips

For very large datasets (>100K events):
1. Filter by timewindow or IP before parsing
2. Use `--incident-id` to analyze specific incidents
3. Split JSONL files by timewindow

## Comparison with slips_dag_generator.py

| Feature | alert_dag_parser.py | slips_dag_generator.py |
|---------|---------------------|------------------------|
| **Input format** | JSONL (IDEA format) | Plain text logs |
| **Classification** | Structured fields | Regex on descriptions |
| **Future-proof** | ✅ Yes | ❌ Requires updates |
| **Analysis mode** | Per-incident only | Per-IP or per-analysis |
| **Output formats** | Comprehensive only | 5 formats (compact, minimal, etc.) |
| **New alert types** | Work automatically | Need code updates |
| **Maintenance** | Low | High (regex patterns) |

### When to Use Each Tool

**Use `alert_dag_parser.py` when:**
- Working with JSONL/IDEA format files
- Need future-proof classification
- Want per-incident comprehensive analysis
- Analyzing structured alert exports

**Use `slips_dag_generator.py` when:**
- Working with plain text Slips logs
- Need multiple output formats
- Want IP-based timeline analysis
- Analyzing real-time log streams

## Limitations

1. **Format dependency** - Only works with JSONL/IDEA format
2. **Memory bound** - All data loaded into memory (not streaming)
3. **Single output format** - Comprehensive analysis only (no minimal/compact modes)
4. **No IP grouping** - Per-incident analysis only, not per-IP
5. **Description fallback** - Unknown patterns use description prefix (not ideal but graceful)

## Future Enhancements

Potential improvements:

1. **Streaming parser** - For very large files
2. **Multiple output formats** - Add compact, minimal, pattern modes
3. **Filtering options** - By severity, timewindow, IP range
4. **Statistical analysis** - Incident trends, severity distribution
5. **Export formats** - JSON, CSV, HTML reports
6. **IP-based grouping** - Optional IP-centric analysis mode
7. **Custom grouping** - User-defined grouping criteria

## Troubleshooting

### Common Issues

**"File not found"**
```bash
# Check path is correct
ls -l alerts.json

# Use absolute path
python3 alert_dag_parser.py /full/path/to/alerts.json
```

**"No incidents found"**
```bash
# Check file format
head -1 alerts.json | python3 -m json.tool

# Verify Status field
grep -o '"Status": "[^"]*"' alerts.json | sort | uniq -c
```

**"Event XYZ not found for Incident ABC"**
- Event referenced in CorrelID but not in file
- Possible file truncation or corruption
- Analysis continues with warning

### Debug Mode

Enable verbose output to see parsing details:
```bash
python3 alert_dag_parser.py alerts.json --verbose 2>&1 | tee debug.log
```

## Contributing

When modifying the tool:

1. **Maintain field-based classification** - Don't add regex on descriptions
2. **Graceful fallbacks** - Unknown patterns should work, not crash
3. **Test with sample datasets** - Use CTU malware capture data
4. **Update this documentation** - Keep examples current

### Testing Checklist

- [ ] Parse all sample datasets without errors
- [ ] Verify incident-event correlation
- [ ] Check output formatting
- [ ] Test all CLI options
- [ ] Handle malformed JSON gracefully
- [ ] Validate with new/unknown alert types

## License

Part of the slips-tools repository. See main repository for license information.

## Related Tools

- `slips_dag_generator.py` - DAG generator for plain text Slips logs
- `analyze_slips_with_llm.sh` - LLM-enhanced analysis wrapper
- Slips IDS - https://github.com/stratosphereips/StratosphereLinuxIPS

## References

- IDEA format specification: https://idea.cesnet.cz/en/index
- Slips documentation: https://stratospherelinuxips.readthedocs.io/
- CTU malware captures: https://www.stratosphereips.org/datasets-overview
