from pathlib import Path
from app.scanner.nmap_parser import parse_nmap_xml


def test_parse_sample_nmap_xml():
    ports = parse_nmap_xml(Path(__file__).resolve().parents[2] / "examples" / "sample_nmap_output.xml")
    assert len(ports) == 3
    assert ports[0]["port"] == 22
    assert ports[1]["service_name"] == "microsoft-ds"
    assert ports[2]["product"] == "MySQL"
