from datetime import datetime


def build_executive_summary(asset: dict, ports: list[dict], changes: list[dict]) -> str:
    high = [p for p in ports if p.get("risk_level") in {"High", "Critical"}]
    new = [c for c in changes if c.get("type") == "new_port"]
    if high:
        return f"Ditemukan {len(high)} layanan berisiko tinggi pada {asset['name']}. Prioritaskan segmentasi jaringan, pembatasan akses, dan validasi kebutuhan bisnis layanan terbuka."
    if new:
        return f"Ditemukan {len(new)} exposure baru sejak scan sebelumnya. Validasi perubahan dan batasi akses sesuai kebutuhan."
    return "Tidak ada risiko tinggi terdeteksi dari passive/light scan ini. Tetap lakukan review manual untuk konfigurasi dan patch level."


def build_markdown_report(asset: dict, scan: dict, ports: list[dict], findings: list[dict], cves: list[dict], changes: list[dict]) -> str:
    summary = build_executive_summary(asset, ports, changes)
    lines = [
        "# SIMRS Cybersecurity Passive Assessment Report",
        "",
        "## Executive Summary",
        summary,
        "",
        "## Target Information",
        f"- Name: {asset['name']}",
        f"- Target: {asset['target']}",
        f"- Environment: {asset.get('environment', 'unknown')}",
        f"- Scan Time: {scan.get('finished_at') or scan.get('started_at') or datetime.utcnow().isoformat()}",
        "",
        "## Open Ports and Services",
        "| Port | Protocol | Service | Product | Version | Risk | Notes |",
        "|---:|---|---|---|---|---|---|",
    ]
    for p in ports:
        lines.append(f"| {p['port']} | {p.get('protocol','tcp')} | {p.get('service_name') or ''} | {p.get('product') or ''} | {p.get('version') or ''} | {p.get('risk_level','Low')} | {p.get('notes') or ''} |")
    lines.extend(["", "## New Findings Since Last Scan"])
    lines.extend([f"- {c['message']}" for c in changes] or ["- Tidak ada perubahan signifikan dari scan sebelumnya."])
    lines.extend(["", "## High Risk Findings"])
    high_findings = [f for f in findings if f.get("risk_level") in {"High", "Critical"}]
    lines.extend([f"- **{f['title']}**: {f['description']} Recommendation: {f['recommendation']}" for f in high_findings] or ["- Tidak ada high risk finding dari rule engine PoC."])
    lines.extend(["", "## Possible CVE Matches", "| CVE ID | Severity | Product | Version | Summary | Recommendation |", "|---|---|---|---|---|---|"])
    for c in cves:
        lines.append(f"| {c.get('cve_id')} | {c.get('severity')} | {c.get('product') or ''} | {c.get('version') or ''} | {c.get('summary')} | {c.get('remediation')} |")
    lines.extend([
        "",
        "## Recommended Actions",
        "- 1 hari: Validasi owner layanan high risk, batasi akses firewall untuk SMB/RDP/database/DICOM, dan review exposure baru.",
        "- 7 hari: Verifikasi patch level, dokumentasikan baseline port yang disetujui, dan aktifkan monitoring log administratif.",
        "- 30 hari: Terapkan segmentasi jaringan SIMRS/PACS/database, review kebijakan backup ransomware, dan perbarui local CVE database.",
        "",
        "## Safety Note",
        "Scan dilakukan menggunakan mode passive/light non-destruktif. Sistem ini tidak melakukan exploit, brute force, credential guessing, bypass, evasion, DoS, fuzzing, atau payload ofensif.",
    ])
    return "\n".join(lines) + "\n"
