from app.risk.rules import evaluate_port


def test_smb_high_risk_and_unknown_version_note():
    result = evaluate_port({"port": 445, "protocol": "tcp", "service_name": "microsoft-ds", "product": "Samba", "version": None})
    assert result["risk_level"] == "High"
    assert "Unknown Version" in result["notes"]
    assert any(f["risk_level"] == "High" for f in result["findings"])


def test_new_ssh_exposure_is_at_least_medium():
    result = evaluate_port({"port": 22, "protocol": "tcp", "service_name": "ssh", "product": "OpenSSH", "version": "9.6"}, is_new=True)
    assert result["risk_level"] == "Medium"
    assert "New Exposure" in result["notes"]
