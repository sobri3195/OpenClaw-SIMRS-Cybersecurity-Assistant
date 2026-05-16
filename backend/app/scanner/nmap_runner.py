import shlex
import subprocess
from pathlib import Path
from uuid import uuid4
from ..config import get_settings

SAFE_BASE_ARGS = ["nmap", "-sV", "-Pn", "-T2", "--open"]
SAFE_VULN_ARGS = ["--script", "vuln and safe"]
FORBIDDEN_NSE_WORDS = {"brute", "exploit", "dos", "fuzzer", "intrusive", "auth", "bypass"}


def build_nmap_command(target: str, output_file: Path, authorized_deep_check: bool = False) -> list[str]:
    settings = get_settings()
    args = [*SAFE_BASE_ARGS, "-oX", str(output_file)]
    if settings.enable_vuln_script and authorized_deep_check:
        if any(word in " ".join(SAFE_VULN_ARGS).lower() for word in FORBIDDEN_NSE_WORDS):
            raise ValueError("Unsafe NSE script selection blocked by guardrails.")
        args.extend(SAFE_VULN_ARGS)
    args.append(target)
    return args


def run_nmap(target: str, authorized_deep_check: bool = False) -> tuple[Path, str]:
    settings = get_settings()
    output_file = settings.scan_output_dir / f"nmap_{uuid4().hex}.xml"
    command = build_nmap_command(target, output_file, authorized_deep_check)
    subprocess.run(command, check=True, timeout=settings.scan_timeout_seconds, capture_output=True, text=True)
    return output_file, " ".join(shlex.quote(part) for part in command)
