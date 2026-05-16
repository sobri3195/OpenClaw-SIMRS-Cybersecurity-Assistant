import json
import re
from functools import lru_cache
from pathlib import Path
from packaging.version import InvalidVersion, Version

DB_PATH = Path(__file__).resolve().parents[2] / "local_cve_db.json"
NO_MATCH = {
    "cve_id": "NO-LOCAL-MATCH",
    "severity": "Info",
    "summary": "No local CVE match found, manual review recommended.",
    "remediation": "Review vendor advisories and update the local CVE database for production use.",
}


@lru_cache
def load_cve_db(path: str | None = None) -> list[dict]:
    with open(path or DB_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _extract_version(version: str | None) -> Version | None:
    if not version:
        return None
    match = re.search(r"\d+(?:\.\d+){0,3}", version)
    if not match:
        return None
    try:
        return Version(match.group(0))
    except InvalidVersion:
        return None


def _in_range(v: Version | None, min_v: str | None, max_v: str | None) -> bool:
    if v is None:
        return False
    if min_v and v < Version(min_v):
        return False
    if max_v and v > Version(max_v):
        return False
    return True


def match_cve(product: str | None, version: str | None, db_path: str | None = None) -> list[dict]:
    if not product:
        return [NO_MATCH]
    normalized = product.lower()
    parsed = _extract_version(version)
    matches = []
    for item in load_cve_db(db_path):
        aliases = [item.get("product", ""), *item.get("aliases", [])]
        if not any(alias.lower() in normalized for alias in aliases if alias):
            continue
        if _in_range(parsed, item.get("min_version"), item.get("max_version")):
            matches.append(item)
    return matches or [NO_MATCH]
