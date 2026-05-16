from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(120), index=True)
    target: Mapped[str] = mapped_column(String(255), index=True)
    category: Mapped[str] = mapped_column(String(80), default="SIMRS")
    environment: Mapped[str] = mapped_column(String(80), default="lab")
    owner: Mapped[str | None] = mapped_column(String(120), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    scans: Mapped[list["Scan"]] = relationship(back_populates="asset", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)
    status: Mapped[str] = mapped_column(String(30), default="pending")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    command: Mapped[str | None] = mapped_column(Text, nullable=True)
    xml_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    safety_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    asset: Mapped[Asset] = relationship(back_populates="scans")
    ports: Mapped[list["ScanPort"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    cve_matches: Mapped[list["CVEMatch"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class ScanPort(Base):
    __tablename__ = "scan_ports"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(20))
    state: Mapped[str] = mapped_column(String(30))
    service_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version: Mapped[str | None] = mapped_column(String(120), nullable=True)
    extra_info: Mapped[str | None] = mapped_column(Text, nullable=True)
    scan_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    risk_level: Mapped[str] = mapped_column(String(20), default="Low")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    scan: Mapped[Scan] = relationship(back_populates="ports")
    __table_args__ = (UniqueConstraint("scan_id", "port", "protocol", name="uq_scan_port_proto"),)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(20), nullable=True)
    title: Mapped[str] = mapped_column(String(255))
    risk_level: Mapped[str] = mapped_column(String(20), default="Low")
    description: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[str] = mapped_column(Text)
    finding_type: Mapped[str] = mapped_column(String(80), default="risk_rule")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    scan: Mapped[Scan] = relationship(back_populates="findings")


class CVEMatch(Base):
    __tablename__ = "cve_matches"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version: Mapped[str | None] = mapped_column(String(120), nullable=True)
    cve_id: Mapped[str] = mapped_column(String(40))
    severity: Mapped[str] = mapped_column(String(20))
    summary: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text)
    scan: Mapped[Scan] = relationship(back_populates="cve_matches")


class HoneypotEvent(Base):
    __tablename__ = "honeypot_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_ip: Mapped[str] = mapped_column(String(80))
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    activity_type: Mapped[str] = mapped_column(String(120), default="connection")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    raw: Mapped[str | None] = mapped_column(Text, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    action: Mapped[str] = mapped_column(String(120))
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
