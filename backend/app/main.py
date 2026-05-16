from datetime import datetime, timezone
from pathlib import Path
from fastapi import Depends, FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session, selectinload
from .config import get_settings
from .database import get_db, init_db
from .models import Asset, CVEMatch, Finding, Scan, ScanPort, now_utc
from .schemas import AssetCreate, AssetRead, ScanRead, ScanRequest, ScheduleScanRequest
from .scanner.safety import audit, enforce_rate_limit, validate_scan_request
from .scanner.nmap_runner import run_nmap
from .scanner.nmap_parser import parse_nmap_xml
from .risk.rules import evaluate_port
from .risk.cve_matcher import match_cve
from .comparison.diff_engine import compare_scans
from .reports.markdown_report import build_executive_summary, build_markdown_report
from .reports.csv_export import ports_to_csv
from .ai.ollama_summary import summarize_report
from .honeypot.log_parser import parse_honeypot_log

app = FastAPI(title="OpenClaw SIMRS Cybersecurity Assistant", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
def startup() -> None:
    Path("data").mkdir(exist_ok=True)
    init_db()


def _scan_to_dict(scan: Scan) -> dict:
    return {"id": scan.id, "asset_id": scan.asset_id, "status": scan.status, "started_at": scan.started_at.isoformat(), "finished_at": scan.finished_at.isoformat() if scan.finished_at else None}


def _port_to_dict(port: ScanPort) -> dict:
    return {"host": port.host, "port": port.port, "protocol": port.protocol, "state": port.state, "service_name": port.service_name, "product": port.product, "version": port.version, "extra_info": port.extra_info, "scan_timestamp": port.scan_timestamp.isoformat(), "risk_level": port.risk_level, "notes": port.notes}


def _asset_to_dict(asset: Asset) -> dict:
    return {"id": asset.id, "name": asset.name, "target": asset.target, "category": asset.category, "environment": asset.environment, "owner": asset.owner, "notes": asset.notes}


def _finding_to_dict(f: Finding) -> dict:
    return {"title": f.title, "risk_level": f.risk_level, "description": f.description, "recommendation": f.recommendation, "port": f.port, "protocol": f.protocol, "finding_type": f.finding_type}


def _cve_to_dict(c: CVEMatch) -> dict:
    return {"cve_id": c.cve_id, "severity": c.severity, "product": c.product, "version": c.version, "summary": c.summary, "remediation": c.remediation, "port": c.port}


def _previous_completed_scan(db: Session, asset_id: int, current_scan_id: int | None = None) -> Scan | None:
    query = db.query(Scan).options(selectinload(Scan.ports)).filter(Scan.asset_id == asset_id, Scan.status == "completed")
    if current_scan_id:
        query = query.filter(Scan.id != current_scan_id)
    return query.order_by(Scan.finished_at.desc()).first()


def _process_scan_results(db: Session, asset: Asset, scan: Scan, xml_path: Path) -> None:
    previous = _previous_completed_scan(db, asset.id, scan.id)
    previous_ports = [_port_to_dict(p) for p in previous.ports] if previous else []
    raw_ports = parse_nmap_xml(xml_path)
    previous_map = {(p["port"], p.get("protocol", "tcp")): p for p in previous_ports}

    staged_ports: list[dict] = []
    all_findings: list[dict] = []
    all_cves: list[dict] = []
    for record in raw_ports:
        key = (record["port"], record.get("protocol", "tcp"))
        old = previous_map.get(key)
        is_new = old is None and bool(previous_ports)
        version_changed = old is not None and (old.get("version") or "") != (record.get("version") or "")
        evaluation = evaluate_port(record, is_new=is_new, version_changed=version_changed)
        enriched = {**record, "risk_level": evaluation["risk_level"], "notes": evaluation["notes"]}
        staged_ports.append(enriched)
        all_findings.extend(evaluation["findings"])
        for cve in match_cve(record.get("product"), record.get("version")):
            if cve["cve_id"] == "NO-LOCAL-MATCH":
                continue
            all_cves.append({**cve, "port": record["port"], "product": record.get("product"), "version": record.get("version")})

    changes = compare_scans(previous_ports, staged_ports, asset.name) if previous_ports else []
    for change in changes:
        if change["type"] in {"closed_port", "risk_changed"}:
            all_findings.append({"port": change.get("port"), "protocol": change.get("protocol"), "title": change["type"].replace("_", " ").title(), "risk_level": change.get("risk_level", "Low"), "description": change["message"], "recommendation": "Review change record and verify expected service baseline.", "finding_type": "comparison"})

    for p in staged_ports:
        db.add(ScanPort(scan_id=scan.id, **p))
    for f in all_findings:
        db.add(Finding(scan_id=scan.id, **f))
    for c in all_cves:
        db.add(CVEMatch(scan_id=scan.id, **c))
    scan.status = "completed"
    scan.finished_at = now_utc()
    db.commit()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "safety": "defensive passive/light scanning only"}


@app.post("/assets", response_model=AssetRead)
def create_asset(payload: AssetCreate, db: Session = Depends(get_db)) -> Asset:
    safety = validate_scan_request(payload.target, safety_acknowledged=True)
    if not safety.allowed:
        raise HTTPException(status_code=400, detail=safety.reason)
    asset = Asset(**payload.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    audit(db, "asset_created", f"asset_id={asset.id} target={asset.target}")
    return asset


@app.get("/assets", response_model=list[AssetRead])
def list_assets(db: Session = Depends(get_db)) -> list[Asset]:
    return db.query(Asset).order_by(Asset.created_at.desc()).all()


@app.get("/assets/{asset_id}", response_model=AssetRead)
def get_asset(asset_id: int, db: Session = Depends(get_db)) -> Asset:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    return asset


@app.post("/assets/{asset_id}/scan", response_model=ScanRead)
def run_manual_scan(asset_id: int, payload: ScanRequest, db: Session = Depends(get_db)) -> Scan:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    safety = validate_scan_request(asset.target, payload.safety_acknowledged)
    if not safety.allowed:
        audit(db, "scan_blocked", safety.reason)
        raise HTTPException(400, safety.reason)
    rate = enforce_rate_limit(db, asset)
    if not rate.allowed:
        raise HTTPException(429, rate.reason)
    scan = Scan(asset_id=asset.id, status="running", safety_acknowledged=True)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    try:
        xml_path, command = run_nmap(asset.target, authorized_deep_check=payload.authorized_deep_check)
        scan.command = command
        scan.xml_path = str(xml_path)
        db.commit()
        _process_scan_results(db, asset, scan, xml_path)
        audit(db, "scan_completed", f"scan_id={scan.id} asset_id={asset.id}")
    except Exception as exc:
        scan.status = "failed"
        scan.error = str(exc)
        scan.finished_at = now_utc()
        db.commit()
        audit(db, "scan_failed", f"scan_id={scan.id} error={exc}")
    return db.query(Scan).options(selectinload(Scan.ports), selectinload(Scan.findings), selectinload(Scan.cve_matches)).get(scan.id)


@app.post("/assets/{asset_id}/schedule")
def schedule_scan(asset_id: int, payload: ScheduleScanRequest, db: Session = Depends(get_db)) -> dict:
    if not db.get(Asset, asset_id):
        raise HTTPException(404, "Asset not found")
    audit(db, "scan_schedule_requested", f"asset_id={asset_id} interval_minutes={payload.interval_minutes}")
    return {"status": "accepted", "message": "PoC schedule request recorded. Use cron/systemd to call the manual scan endpoint at the approved interval.", "interval_minutes": payload.interval_minutes}


@app.get("/assets/{asset_id}/scans", response_model=list[ScanRead])
def scan_history(asset_id: int, db: Session = Depends(get_db)) -> list[Scan]:
    return db.query(Scan).options(selectinload(Scan.ports), selectinload(Scan.findings), selectinload(Scan.cve_matches)).filter(Scan.asset_id == asset_id).order_by(Scan.started_at.desc()).all()


@app.get("/scans/{scan_id}", response_model=ScanRead)
def scan_detail(scan_id: int, db: Session = Depends(get_db)) -> Scan:
    scan = db.query(Scan).options(selectinload(Scan.ports), selectinload(Scan.findings), selectinload(Scan.cve_matches)).get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@app.get("/scans/{scan_id}/comparison")
def scan_comparison(scan_id: int, db: Session = Depends(get_db)) -> dict:
    scan = db.query(Scan).options(selectinload(Scan.ports), selectinload(Scan.asset)).get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    previous = _previous_completed_scan(db, scan.asset_id, scan.id)
    changes = compare_scans([_port_to_dict(p) for p in previous.ports] if previous else [], [_port_to_dict(p) for p in scan.ports], scan.asset.name)
    return {"scan_id": scan.id, "previous_scan_id": previous.id if previous else None, "changes": changes}


@app.get("/scans/{scan_id}/report.json")
def report_json(scan_id: int, db: Session = Depends(get_db)) -> dict:
    scan = db.query(Scan).options(selectinload(Scan.asset), selectinload(Scan.ports), selectinload(Scan.findings), selectinload(Scan.cve_matches)).get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    previous = _previous_completed_scan(db, scan.asset_id, scan.id)
    changes = compare_scans([_port_to_dict(p) for p in previous.ports] if previous else [], [_port_to_dict(p) for p in scan.ports], scan.asset.name)
    asset = _asset_to_dict(scan.asset)
    ports = [_port_to_dict(p) for p in scan.ports]
    summary = build_executive_summary(asset, ports, changes)
    data = {"asset": asset, "scan": _scan_to_dict(scan), "ports": ports, "findings": [_finding_to_dict(f) for f in scan.findings], "cve_matches": [_cve_to_dict(c) for c in scan.cve_matches], "comparison": changes, "executive_summary": summary, "safety_note": "Passive/light non-destructive scan only; no exploit, brute force, credential attack, DoS, evasion, or offensive payloads."}
    data["ai_summary"] = summarize_report(data, summary)
    return data


@app.get("/scans/{scan_id}/report.md")
def report_markdown(scan_id: int, db: Session = Depends(get_db)) -> Response:
    data = report_json(scan_id, db)
    md = build_markdown_report(data["asset"], data["scan"], data["ports"], data["findings"], data["cve_matches"], data["comparison"])
    return Response(md, media_type="text/markdown")


@app.get("/scans/{scan_id}/export.csv")
def export_csv(scan_id: int, db: Session = Depends(get_db)) -> Response:
    scan = db.query(Scan).options(selectinload(Scan.ports)).get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return Response(ports_to_csv([_port_to_dict(p) for p in scan.ports]), media_type="text/csv")


@app.get("/dashboard")
def dashboard(db: Session = Depends(get_db)) -> dict:
    last_scan = db.query(Scan).order_by(Scan.started_at.desc()).first()
    high = db.query(Finding).filter(Finding.risk_level.in_(["High", "Critical"])).count()
    new = db.query(Finding).filter(Finding.finding_type == "comparison", Finding.title.like("New Exposure%") ).count()
    return {"total_assets": db.query(Asset).count(), "total_high_risk_findings": high, "new_open_ports": new, "last_scanned_target": last_scan.asset.target if last_scan and last_scan.asset else None}


@app.post("/honeypot/parse")
def parse_honeypot(path: str, db: Session = Depends(get_db)) -> dict:
    result = parse_honeypot_log(path)
    audit(db, "honeypot_log_parsed", f"path={path} events={result['connection_count']}")
    return result
