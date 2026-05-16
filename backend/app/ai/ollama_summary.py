import json
import requests
from ..config import get_settings

PROMPT = "Ringkas laporan keamanan SIMRS berikut untuk pembaca manajerial non-teknis. Jangan menambahkan fakta di luar data. Berikan prioritas risiko dan rekomendasi mitigasi defensif."


def summarize_report(report_json: dict, fallback_summary: str) -> str:
    settings = get_settings()
    if not settings.ollama_enabled:
        return fallback_summary
    try:
        response = requests.post(
            settings.ollama_url,
            json={"model": settings.ollama_model, "prompt": f"{PROMPT}\n\n{json.dumps(report_json, ensure_ascii=False)}", "stream": False},
            timeout=20,
        )
        response.raise_for_status()
        return response.json().get("response") or fallback_summary
    except requests.RequestException:
        return fallback_summary
