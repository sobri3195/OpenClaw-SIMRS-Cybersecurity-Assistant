RISK_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
HIGH_RISK_PORTS = {
    445: ("High", "SMB exposure can enable ransomware lateral movement and unsafe file sharing."),
    3306: ("High", "MySQL exposure may risk unauthorized access to patient databases."),
    5432: ("High", "PostgreSQL exposure may risk unauthorized access to patient databases."),
    104: ("High", "DICOM/PACS exposure can affect medical imaging confidentiality."),
    11112: ("High", "DICOM/PACS exposure can affect medical imaging confidentiality."),
    3389: ("High", "RDP exposure is commonly abused for remote access compromise."),
}
RECOMMENDATIONS = {
    445: "Restrict SMB to required internal subnets, disable legacy SMB versions, and audit file share permissions.",
    3306: "Bind database services to application hosts only, enforce firewall rules, and verify database access logs.",
    5432: "Bind database services to application hosts only, enforce firewall rules, and verify database access logs.",
    104: "Restrict DICOM/PACS access to modality and PACS subnets, require network segmentation, and review AE titles.",
    11112: "Restrict DICOM/PACS access to modality and PACS subnets, require network segmentation, and review AE titles.",
    3389: "Disable direct RDP where possible, require VPN/MFA jump host access, and monitor remote login events.",
    22: "Restrict SSH to administration subnet, enforce key-based access, and monitor administrative logins.",
}


def max_risk(a: str, b: str) -> str:
    return a if RISK_ORDER[a] >= RISK_ORDER[b] else b


def evaluate_port(record: dict, is_new: bool = False, version_changed: bool = False) -> dict:
    port = int(record["port"])
    service = (record.get("service_name") or "unknown").lower()
    product = record.get("product") or ""
    version = record.get("version") or ""
    risk = "Low"
    notes: list[str] = []
    findings: list[dict] = []

    if port in HIGH_RISK_PORTS:
        risk, note = HIGH_RISK_PORTS[port]
        notes.append(note)
        findings.append({
            "port": port,
            "protocol": record.get("protocol"),
            "title": f"High-risk service exposed on {port}/{service.upper()}",
            "risk_level": risk,
            "description": note,
            "recommendation": RECOMMENDATIONS[port],
            "finding_type": "risk_rule",
        })
    elif port in {80, 443} or service in {"http", "https", "http-proxy"}:
        risk = "Medium"
        notes.append("Web service should be reviewed for patching, TLS, and exposed administration paths.")
        if any(term in f"{product} {version}".lower() for term in ["apache 2.2", "iis 6", "tomcat"]):
            risk = "High"
            notes.append("Banner suggests a legacy or sensitive web component.")
    elif port == 22 or service == "ssh":
        risk = "Medium"
        notes.append("SSH administrative service detected; restrict access to trusted management networks.")

    if is_new:
        risk = max_risk(risk, "Medium")
        notes.append("New Exposure")
        findings.append({
            "port": port,
            "protocol": record.get("protocol"),
            "title": f"New Exposure: {port}/{service}",
            "risk_level": risk,
            "description": f"Port {port}/{service} baru terdeteksi terbuka pada aset ini.",
            "recommendation": RECOMMENDATIONS.get(port, "Verify business need, restrict access with firewall rules, and document the approved owner."),
            "finding_type": "comparison",
        })
    if version_changed:
        notes.append("Service Version Changed")
    if not version:
        notes.append("Unknown Version – Manual Review Needed")
        findings.append({
            "port": port,
            "protocol": record.get("protocol"),
            "title": f"Unknown version for {port}/{service}",
            "risk_level": max_risk(risk, "Medium"),
            "description": "Service version was not identified by passive/light service detection.",
            "recommendation": "Perform manual configuration review and verify patch level from the asset owner.",
            "finding_type": "manual_review",
        })
    return {"risk_level": risk, "notes": "; ".join(notes), "findings": findings}
