from datetime import datetime
from pydantic import BaseModel, Field


class AssetBase(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    target: str = Field(min_length=1, max_length=255, description="Private/local IP or internal hostname by default")
    category: str = "SIMRS"
    environment: str = "lab"
    owner: str | None = None
    notes: str | None = None


class AssetCreate(AssetBase):
    pass


class AssetRead(AssetBase):
    id: int
    created_at: datetime
    model_config = {"from_attributes": True}


class ScanRequest(BaseModel):
    safety_acknowledged: bool = Field(default=False, description="User confirms authorization to scan this asset")
    authorized_deep_check: bool = False


class ScanPortRead(BaseModel):
    id: int
    host: str
    port: int
    protocol: str
    state: str
    service_name: str | None
    product: str | None
    version: str | None
    extra_info: str | None
    scan_timestamp: datetime
    risk_level: str
    notes: str | None
    model_config = {"from_attributes": True}


class FindingRead(BaseModel):
    id: int
    port: int | None
    protocol: str | None
    title: str
    risk_level: str
    description: str
    recommendation: str
    finding_type: str
    model_config = {"from_attributes": True}


class CVEMatchRead(BaseModel):
    id: int
    port: int | None
    product: str | None
    version: str | None
    cve_id: str
    severity: str
    summary: str
    remediation: str
    model_config = {"from_attributes": True}


class ScanRead(BaseModel):
    id: int
    asset_id: int
    status: str
    started_at: datetime
    finished_at: datetime | None
    command: str | None
    error: str | None
    ports: list[ScanPortRead] = []
    findings: list[FindingRead] = []
    cve_matches: list[CVEMatchRead] = []
    model_config = {"from_attributes": True}


class ScheduleScanRequest(BaseModel):
    interval_minutes: int = Field(ge=30, le=10080)
    safety_acknowledged: bool = False


class ReportJSON(BaseModel):
    scan: ScanRead
    executive_summary: str
    comparison: list[dict]
    safety_note: str
