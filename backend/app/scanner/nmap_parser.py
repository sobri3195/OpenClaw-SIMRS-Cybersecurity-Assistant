from datetime import datetime, timezone
from pathlib import Path
import xml.etree.ElementTree as ET


def _timestamp(root: ET.Element) -> datetime:
    started = root.attrib.get("start")
    if started and started.isdigit():
        return datetime.fromtimestamp(int(started), tz=timezone.utc)
    return datetime.now(timezone.utc)


def parse_nmap_xml(xml_file: str | Path) -> list[dict]:
    root = ET.parse(xml_file).getroot()
    scan_time = _timestamp(root)
    records: list[dict] = []
    for host in root.findall("host"):
        address_el = host.find("address")
        host_addr = address_el.attrib.get("addr", "unknown") if address_el is not None else "unknown"
        for port_el in host.findall("ports/port"):
            state_el = port_el.find("state")
            service_el = port_el.find("service")
            state = state_el.attrib.get("state", "unknown") if state_el is not None else "unknown"
            if state != "open":
                continue
            records.append(
                {
                    "host": host_addr,
                    "port": int(port_el.attrib["portid"]),
                    "protocol": port_el.attrib.get("protocol", "tcp"),
                    "state": state,
                    "service_name": service_el.attrib.get("name") if service_el is not None else None,
                    "product": service_el.attrib.get("product") if service_el is not None else None,
                    "version": service_el.attrib.get("version") if service_el is not None else None,
                    "extra_info": service_el.attrib.get("extrainfo") if service_el is not None else None,
                    "scan_timestamp": scan_time,
                }
            )
    return records
