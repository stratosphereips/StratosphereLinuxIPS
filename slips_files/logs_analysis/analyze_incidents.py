#!/usr/bin/env python3
import json
import sys
from pathlib import Path
import glob

# --- Colors ---
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
GRAY = "\033[90m"
BLUE = "\033[94m"

def usage():
    print(f"Usage: {sys.argv[0]} <alerts.json> <type> <id> <zeek_folder> [--debug]")
    print("  <type>: 'incident' or 'event'")
    sys.exit(1)

def load_jsonl(path):
    """Yield parsed JSON objects (line-delimited JSON)."""
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue

def load_zeek_log(path):
    """Load a Zeek log file (JSON or TSV) and index by UID or UIDs."""
    flows = {}
    headers = set()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                flow = None

                # JSON log (modern Zeek format)
                if line.startswith("{"):
                    try:
                        flow = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                else:
                    # TSV fallback
                    if line.startswith("#fields"):
                        headers.update(line.split()[1:])
                        continue
                    parts = line.split("\t")
                    if headers and len(parts) == len(headers):
                        flow = dict(zip(list(headers), parts))

                if not flow:
                    continue

                headers.update(flow.keys())

                # Normalize UID handling
                uids = []
                if "uid" in flow:
                    uids = [flow["uid"]]
                elif "uids" in flow and isinstance(flow["uids"], list):
                    uids = flow["uids"]

                for uid in uids:
                    if uid:
                        flows.setdefault(uid.strip(), []).append(flow)
    except Exception as e:
        print(f"{RED}Error parsing {path}:{RESET} {e}")
    return flows, sorted(headers)

def parse_note_uids(note_str):
    """Extract UIDs from the Note JSON string inside an Event."""
    if not note_str:
        return []
    try:
        note = json.loads(note_str)
        if isinstance(note, str):
            note = json.loads(note)
        if isinstance(note, dict):
            return note.get("uids", [])
    except Exception:
        pass
    return []

def show_event(event, log_files, logs_data, debug=False):
    """Show an event and all matching Zeek flows with all columns per log type."""
    eid = event.get("ID")
    desc = event.get("Description", "").replace("\n", " ").strip()
    sev = event.get("Severity", "Unknown")
    src_ips = ", ".join(sv.get("IP") for sv in event.get("Source", []) if sv.get("IP"))
    uids = parse_note_uids(event.get("Note", "{}"))

    sev_color = {"Low": GREEN, "Medium": YELLOW, "High": RED, "Critical": MAGENTA}.get(sev, RESET)

    print(f"{BOLD}{CYAN}Event:{RESET} {eid}")
    print(f"  {BOLD}Severity:{RESET} {sev_color}{sev}{RESET}")
    print(f"  {BOLD}Source IP(s):{RESET} {src_ips}")
    print(f"  {BOLD}Description:{RESET} {desc}")
    print(f"  {BOLD}UIDs from Note:{RESET} {uids if uids else '(none)'}")

    if not uids:
        print(f"  {GRAY}(no flow UIDs in Note){RESET}")
        print(f"{GRAY}{'-'*120}{RESET}")
        return

    # --- Search all Zeek logs for these UIDs ---
    matched = []
    for lf in log_files:
        for uid in uids:
            if uid in logs_data[lf]["flows"]:
                for row in logs_data[lf]["flows"][uid]:
                    matched.append((row, Path(lf).name))

    if not matched:
        print(f"  {GRAY}(no matching flows found in Zeek logs){RESET}")
        print(f"{GRAY}{'-'*120}{RESET}")
        return

    print(f"\n  {BOLD}{MAGENTA}Flows found:{RESET} {len(matched)}")
    print(f"{GRAY}{'-'*120}{RESET}")

    # Group by log file
    by_file = {}
    for flow, fname in matched:
        by_file.setdefault(fname, []).append(flow)

    for fname, flows in by_file.items():
        print(f"{BOLD}{BLUE}{fname}:{RESET}")
        all_fields = sorted({k for f in flows for k in f.keys()})
        widths = {k: len(k) for k in all_fields}
        for f in flows:
            for k in all_fields:
                val = str(f.get(k, "-"))
                if len(val) > widths[k]:
                    widths[k] = min(len(val), 80)  # avoid super wide columns

        # Header
        header_line = "  " + "  ".join(f"{CYAN}{BOLD}{h.ljust(widths[h])}{RESET}" for h in all_fields)
        print(header_line)
        print("  " + "-" * (len(header_line) - 2))

        # Rows
        for f in sorted(flows, key=lambda x: float(x.get("ts", 0)) if "ts" in x else 0):
            row = "  " + "  ".join(
                str(f.get(h, "-"))[:widths[h]].ljust(widths[h]) for h in all_fields
            )
            print(row)
        print(f"{GRAY}{'-'*120}{RESET}")

def main():
    if len(sys.argv) < 5:
        usage()

    alerts_file = Path(sys.argv[1])
    mode = sys.argv[2].lower()
    target_id = sys.argv[3]
    zeek_folder = Path(sys.argv[4])
    debug = "--debug" in sys.argv

    if mode not in ("incident", "event"):
        usage()

    if not alerts_file.exists():
        sys.exit(f"{RED}Alerts file not found:{RESET} {alerts_file}")
    if not zeek_folder.exists():
        sys.exit(f"{RED}Zeek folder not found:{RESET} {zeek_folder}")

    # --- Load alerts ---
    incidents, events = [], []
    for obj in load_jsonl(alerts_file):
        if obj.get("Status") == "Incident":
            incidents.append(obj)
        elif obj.get("Status") == "Event":
            events.append(obj)

    # --- Load all .log files (recursively) ---
    log_files = sorted(glob.glob(str(zeek_folder / "**" / "*.log"), recursive=True))
    if not log_files:
        sys.exit(f"{RED}No .log files found in folder:{RESET} {zeek_folder}")

    logs_data = {}
    for lf in log_files:
        flows, headers = load_zeek_log(lf)
        logs_data[lf] = {"flows": flows, "headers": headers}
        if debug:
            print(f"{GRAY}Loaded {len(flows)} UIDs from {Path(lf).name}{RESET}")
            if headers:
                print(f"  {BOLD}{BLUE}Columns ({len(headers)}):{RESET} {', '.join(sorted(headers))}\n")

    # --- Main logic ---
    if mode == "incident":
        incident = next((i for i in incidents if i.get("ID") == target_id), None)
        if not incident:
            sys.exit(f"{RED}Incident {target_id} not found.{RESET}")

        correl_ids = set(incident.get("CorrelID", []))
        related_events = [e for e in events if e.get("ID") in correl_ids]

        print(f"\n{BOLD}{CYAN}Incident:{RESET} {target_id}")
        print(f"{GRAY}{'-'*120}{RESET}")

        if not related_events:
            print(f"{YELLOW}(No related events found){RESET}")
            return

        for ev in related_events:
            show_event(ev, log_files, logs_data, debug=debug)

    elif mode == "event":
        event = next((e for e in events if e.get("ID") == target_id), None)
        if not event:
            sys.exit(f"{RED}Event {target_id} not found.{RESET}")

        print(f"\n{BOLD}{CYAN}Analyzing single Event:{RESET} {target_id}")
        print(f"{GRAY}{'-'*120}{RESET}")
        show_event(event, log_files, logs_data, debug=debug)

if __name__ == "__main__":
    main()
