from app.comparison.diff_engine import compare_scans


def test_compare_detects_new_closed_and_version_changed():
    previous = [{"port": 22, "protocol": "tcp", "service_name": "ssh", "version": "8.9", "risk_level": "Medium"}, {"port": 80, "protocol": "tcp", "service_name": "http", "version": "1.0", "risk_level": "Medium"}]
    current = [{"port": 22, "protocol": "tcp", "service_name": "ssh", "version": "9.6", "risk_level": "Medium"}, {"port": 445, "protocol": "tcp", "service_name": "microsoft-ds", "version": "4.7", "risk_level": "High"}]
    changes = compare_scans(previous, current, "Server SIMRS")
    types = {c["type"] for c in changes}
    assert {"version_changed", "new_port", "closed_port"}.issubset(types)
