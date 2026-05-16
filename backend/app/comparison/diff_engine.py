def _key(port: dict) -> tuple[int, str]:
    return int(port["port"]), port.get("protocol", "tcp")


def compare_scans(previous_ports: list[dict], current_ports: list[dict], asset_name: str = "asset") -> list[dict]:
    previous = {_key(p): p for p in previous_ports}
    current = {_key(p): p for p in current_ports}
    changes: list[dict] = []
    for key, port in current.items():
        port_no, proto = key
        service = port.get("service_name") or "unknown"
        old = previous.get(key)
        if old is None:
            changes.append({
                "type": "new_port",
                "port": port_no,
                "protocol": proto,
                "risk_level": port.get("risk_level", "Medium"),
                "message": f"Port {port_no}/{service} baru terdeteksi terbuka pada {asset_name}. Ini dapat meningkatkan exposure layanan. Rekomendasi: validasi kebutuhan bisnis dan batasi akses hanya dari subnet yang diperlukan.",
            })
            continue
        if (old.get("service_name"), old.get("product")) != (port.get("service_name"), port.get("product")):
            changes.append({"type": "service_changed", "port": port_no, "protocol": proto, "risk_level": port.get("risk_level", "Medium"), "message": f"Service pada port {port_no}/{proto} berubah dari {old.get('service_name') or 'unknown'} menjadi {service}. Rekomendasi: konfirmasi perubahan ini terencana."})
        if (old.get("version") or "") != (port.get("version") or ""):
            changes.append({"type": "version_changed", "port": port_no, "protocol": proto, "risk_level": port.get("risk_level", "Medium"), "message": f"Versi service pada port {port_no}/{proto} berubah dari {old.get('version') or 'unknown'} menjadi {port.get('version') or 'unknown'}. Rekomendasi: verifikasi patch/change record."})
        if old.get("risk_level") and old.get("risk_level") != port.get("risk_level"):
            changes.append({"type": "risk_changed", "port": port_no, "protocol": proto, "risk_level": port.get("risk_level", "Medium"), "message": f"Risk level port {port_no}/{proto} berubah dari {old.get('risk_level')} menjadi {port.get('risk_level')}."})
    for key, port in previous.items():
        if key not in current:
            changes.append({"type": "closed_port", "port": key[0], "protocol": key[1], "risk_level": "Low", "message": f"Port {key[0]}/{port.get('service_name') or 'unknown'} tidak lagi terdeteksi terbuka pada {asset_name}."})
    return changes
