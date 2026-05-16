import ipaddress
import re
import socket
import time
from dataclasses import dataclass
from sqlalchemy.orm import Session
from ..config import get_settings
from ..models import Asset, AuditLog, Scan

_LOCAL_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home", ".corp")
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")


@dataclass
class SafetyResult:
    allowed: bool
    reason: str


def is_private_or_local_target(target: str) -> bool:
    raw = target.strip()
    try:
        ip = ipaddress.ip_address(raw)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        pass
    lowered = raw.lower().rstrip(".")
    if lowered in {"localhost"} or lowered.endswith(_LOCAL_SUFFIXES):
        return True
    if not _HOST_RE.fullmatch(raw):
        return False
    try:
        infos = socket.getaddrinfo(raw, None)
    except socket.gaierror:
        # Unresolved internal names are allowed so users can register split-DNS lab assets.
        return "." not in raw or lowered.endswith(_LOCAL_SUFFIXES)
    return all(ipaddress.ip_address(info[4][0]).is_private for info in infos)


def validate_scan_request(target: str, safety_acknowledged: bool) -> SafetyResult:
    if not safety_acknowledged:
        return SafetyResult(False, "Legal/authorization warning must be acknowledged before scanning.")
    if not is_private_or_local_target(target) and not get_settings().allow_public_scan:
        return SafetyResult(False, "Public targets are blocked by default. Set ALLOW_PUBLIC_SCAN=true only for explicitly authorized assets.")
    return SafetyResult(True, "Allowed for passive/light scanning.")


def enforce_rate_limit(db: Session, asset: Asset) -> SafetyResult:
    settings = get_settings()
    latest = (
        db.query(Scan)
        .filter(Scan.asset_id == asset.id, Scan.status.in_(["completed", "failed", "running"]))
        .order_by(Scan.started_at.desc())
        .first()
    )
    if not latest:
        return SafetyResult(True, "No previous scan.")
    elapsed = time.time() - latest.started_at.timestamp()
    if elapsed < settings.min_seconds_between_scans_per_asset:
        return SafetyResult(False, f"Rate limit active. Wait {int(settings.min_seconds_between_scans_per_asset - elapsed)} seconds before scanning this asset again.")
    return SafetyResult(True, "Rate limit passed.")


def audit(db: Session, action: str, details: str | None = None) -> None:
    db.add(AuditLog(action=action, details=details))
    db.commit()
