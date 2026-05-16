import json
import re
from collections import Counter
from pathlib import Path

IP_RE = re.compile(r"(?P<src>\b(?:\d{1,3}\.){3}\d{1,3}\b).*(?:dpt|dst_port|port)[=: ](?P<port>\d{1,5})", re.I)


def parse_honeypot_log(path: str) -> dict:
    file_path = Path(path)
    events = []
    for line in file_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        event = None
        try:
            data = json.loads(line)
            event = {
                "timestamp": data.get("timestamp") or data.get("@timestamp"),
                "source_ip": data.get("src_ip") or data.get("source_ip") or data.get("src"),
                "destination_port": data.get("dst_port") or data.get("destination_port") or data.get("port"),
                "activity_type": data.get("type") or data.get("event_type") or "connection",
                "raw": line,
            }
        except json.JSONDecodeError:
            match = IP_RE.search(line)
            if match:
                event = {"timestamp": None, "source_ip": match.group("src"), "destination_port": int(match.group("port")), "activity_type": "connection", "raw": line}
        if event and event.get("source_ip"):
            events.append(event)
    top_sources = Counter(e["source_ip"] for e in events).most_common(10)
    return {"connection_count": len(events), "top_source_ips": top_sources, "events": events, "summary": f"Detected {len(events)} honeypot log events from {len(top_sources)} notable sources. Data stayed local."}
