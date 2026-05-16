from functools import lru_cache
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "OpenClaw SIMRS Cybersecurity Assistant"
    database_url: str = "sqlite:///./data/openclaw.db"
    scan_output_dir: Path = Path("./data/scans")
    allow_public_scan: bool = False
    enable_vuln_script: bool = False
    authorized_deep_check: bool = False
    scan_timeout_seconds: int = 120
    min_seconds_between_scans_per_asset: int = 300
    ollama_enabled: bool = False
    ollama_url: str = "http://ollama:11434/api/generate"
    ollama_model: str = "llama3"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.scan_output_dir.mkdir(parents=True, exist_ok=True)
    return settings
