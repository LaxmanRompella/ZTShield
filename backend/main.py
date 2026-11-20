import ipaddress
import hashlib
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic_settings import BaseSettings, SettingsConfigDict
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import (
    String,
    URL,
    create_engine,
    select,
    ForeignKey,
    UniqueConstraint,
    Text,
    Integer,
    Index,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    sessionmaker,
    relationship,
)


# Database: backend/ztshield.db
BASE_DIR = Path(__file__).resolve().parent
DATABASE_URL = URL.create(
    "sqlite",
    database=str(BASE_DIR / "ztshield.db"),
)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


Severity = Literal["Critical", "High", "Medium", "Low"]

class Settings(BaseSettings):
    ingest_token: str = Field(min_length=64, max_length=64)
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        env_prefix="ZTSHIELD_",
        extra="ignore",
    )


settings = Settings()
print(
    f"ZTShield CORS allowlist: {settings.cors_origins!r}",
    flush=True,
)

class Alert(Base):
    __tablename__ = "alerts"

    event_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    timestamp: Mapped[str] = mapped_column(String(40), index=True)
    title: Mapped[str] = mapped_column(String(200))
    source_ip: Mapped[str] = mapped_column(String(100))
    destination: Mapped[str] = mapped_column(String(100))
    protocol: Mapped[str] = mapped_column(String(30))
    zone: Mapped[str] = mapped_column(String(30))
    severity: Mapped[str] = mapped_column(String(20), index=True)
    status: Mapped[str] = mapped_column(String(30), default="New")
    source_type: Mapped[str] = mapped_column(String(30), default="manual")


class Incident(Base):
    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_level: Mapped[str] = mapped_column(String(20), index=True)
    status: Mapped[str] = mapped_column(String(30), default="Open", index=True)
    assigned_to: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[str] = mapped_column(String(40), index=True)
    updated_at: Mapped[str] = mapped_column(String(40))

    evidence: Mapped[list["IncidentEvidence"]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
    )
    timeline: Mapped[list["IncidentTimeline"]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentTimeline.created_at",
    )


class IncidentDetection(Base):
    __tablename__ = "incident_detections"
    __table_args__ = (
        UniqueConstraint(
            "detection_key",
            name="uq_incident_detection_key",
        ),
        Index(
            "ix_incident_detections_incident_id",
            "incident_id",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
    )
    detection_key: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    detection_type: Mapped[str] = mapped_column(
        String(60),
        nullable=False,
    )
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
    )
    updated_at: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
    )

    incident: Mapped["Incident"] = relationship()



class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"
    __table_args__ = (
        UniqueConstraint(
            "incident_id",
            "event_id",
            name="uq_incident_event_evidence",
        ),
        Index("ix_incident_evidence_event_id", "event_id"),
    )

    evidence_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_id: Mapped[str] = mapped_column(
        ForeignKey("alerts.event_id", ondelete="RESTRICT"),
        nullable=False,
    )
    evidence_type: Mapped[str] = mapped_column(String(50), default="alert")
    explanation: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[str] = mapped_column(String(40))

    incident: Mapped["Incident"] = relationship(back_populates="evidence")
    alert: Mapped["Alert"] = relationship()


class IncidentTimeline(Base):
    __tablename__ = "incident_timeline"

    timeline_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    details: Mapped[str] = mapped_column(Text, default="")
    actor: Mapped[str] = mapped_column(String(100), default="system")
    created_at: Mapped[str] = mapped_column(String(40), index=True)

    incident: Mapped["Incident"] = relationship(back_populates="timeline")



class AlertCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    source_ip: str = Field(min_length=1, max_length=100)
    destination: str = Field(min_length=1, max_length=100)
    protocol: str = Field(min_length=1, max_length=30)
    zone: str = Field(min_length=1, max_length=30)
    severity: Severity
    status: str = Field(default="New", max_length=30)
    


class SuricataAlertDetails(BaseModel):
    signature: str = Field(min_length=1, max_length=200)
    severity: int = Field(default=3, ge=1, le=4)
    category: str | None = Field(default=None, max_length=100)


class SuricataEveInput(BaseModel):
    event_type: str = Field(min_length=1, max_length=30)
    timestamp: str | None = Field(default=None, max_length=40)
    src_ip: str = Field(min_length=1, max_length=100)
    dest_ip: str = Field(min_length=1, max_length=100)
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dest_port: int | None = Field(default=None, ge=0, le=65535)
    proto: str = Field(default="UNKNOWN", max_length=30)
    alert: SuricataAlertDetails | None = None
    


class PfsenseFilterLogInput(BaseModel):
    timestamp: str = Field(min_length=1, max_length=40)

    action: Literal["pass", "block"]
    interface: str = Field(min_length=1, max_length=30)
    reason: str = Field(default="match", max_length=30)
    direction: Literal["in", "out"]

    ip_version: Literal[4, 6]
    protocol: str = Field(min_length=1, max_length=30)

    src_ip: str = Field(min_length=1, max_length=100)
    dest_ip: str = Field(min_length=1, max_length=100)

    src_port: int | None = Field(default=None, ge=0, le=65535)
    dest_port: int | None = Field(default=None, ge=0, le=65535)

    rule_number: str = Field(min_length=1, max_length=30)
    rule_tracker: str | None = Field(default=None, max_length=40)
    
    severity: Literal["info", "low", "medium", "high", "critical"]



class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: str
    timestamp: str
    title: str
    source_ip: str
    destination: str
    protocol: str
    zone: str
    severity: str
    status: str
    source_type: str



IncidentStatus = Literal[
    "Open",
    "Investigating",
    "Resolved",
    "Closed",
]


class IncidentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    risk_level: Severity
    assigned_to: str | None = Field(default=None, max_length=100)
    evidence_event_ids: list[str] = Field(default_factory=list)


class IncidentStatusUpdate(BaseModel):
    status: IncidentStatus
    actor: str = Field(default="system", min_length=1, max_length=100)
    details: str = Field(default="", max_length=2000)


class IncidentEvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    evidence_id: str
    event_id: str
    evidence_type: str
    explanation: str
    created_at: str


class IncidentTimelineOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    timeline_id: str
    action: str
    details: str
    actor: str
    created_at: str


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    incident_id: str
    title: str
    description: str
    severity: str
    risk_score: int
    risk_level: str
    status: str
    assigned_to: str | None
    created_at: str
    updated_at: str
    evidence: list[IncidentEvidenceOut]
    timeline: list[IncidentTimelineOut]



def get_db():
    with SessionLocal() as db:
        yield db
        

def verify_ingest_token(
    x_ztshield_token: str | None = Header(default=None),
):
    if x_ztshield_token is None or not secrets.compare_digest(
        x_ztshield_token,
        settings.ingest_token,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing ingestion token.",
        )


def seed_demo_data(db: Session) -> None:
    """Insert clearly labelled demo events only into an empty database."""
    if db.scalar(select(Alert.event_id).limit(1)) is not None:
        return

    examples = [
        {
            "title": "Repeated authentication failures",
            "source_ip": "192.168.10.24",
            "destination": "192.168.20.10",
            "protocol": "SSH",
            "zone": "SERVER",
            "severity": "High",
            "status": "Investigate",
        },
        {
            "title": "Port scan detected",
            "source_ip": "192.168.10.50",
            "destination": "192.168.20.0/24",
            "protocol": "TCP",
            "zone": "USER",
            "severity": "High",
            "status": "Investigate",
        },
        {
            "title": "Blocked inter-zone connection",
            "source_ip": "192.168.30.12",
            "destination": "192.168.10.24",
            "protocol": "TCP",
            "zone": "DMZ",
            "severity": "Medium",
            "status": "Blocked",
        },
        {
            "title": "Suspicious HTTP request pattern",
            "source_ip": "192.168.30.18",
            "destination": "192.168.30.5",
            "protocol": "HTTP",
            "zone": "DMZ",
            "severity": "Critical",
            "status": "Investigate",
        },
        {
            "title": "Unexpected outbound connection",
            "source_ip": "192.168.20.10",
            "destination": "203.0.113.10",
            "protocol": "TCP",
            "zone": "SERVER",
            "severity": "Low",
            "status": "Review",
        },
    ]

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    for index, example in enumerate(examples, start=1):
        db.add(
            Alert(
                event_id=f"DEMO-{index:04d}",
                timestamp=now,
                source_type="demo",
                **example,
            )
        )

    db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        seed_demo_data(db)

    yield


app = FastAPI(
    title="ZTShield API",
    description=(
        "Security event management API. "
        "Initial database records are illustrative demo data."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in settings.cors_origins.split(",")
        if origin.strip()
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.get("/")
def root():
    return {
        "name": "ZTShield API",
        "version": "0.1.0",
        "documentation": "/docs",
    }


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "ztshield-api",
        "database": "sqlite",
        "mode": "local-development",
    }


@app.get("/api/alerts", response_model=list[AlertOut])
def list_alerts(
    severity: Severity | None = None,
    q: str | None = Query(default=None, max_length=100),
    db: Session = Depends(get_db),
):
    statement = select(Alert).order_by(Alert.timestamp.desc())

    if severity:
        statement = statement.where(Alert.severity == severity)

    alerts = list(db.scalars(statement).all())

    if q:
        term = q.casefold()
        alerts = [
            alert
            for alert in alerts
            if term
            in " ".join(
                [
                    alert.event_id,
                    alert.title,
                    alert.source_ip,
                    alert.destination,
                    alert.protocol,
                    alert.zone,
                    alert.status,
                ]
            ).casefold()
        ]

    return alerts



@app.post(
    "/api/incidents",
    response_model=IncidentOut,
    status_code=201,
)
def create_incident(
    payload: IncidentCreate,
    db: Session = Depends(get_db),
):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    incident_id = str(uuid4())

    # Remove duplicate evidence IDs while preserving their order.
    event_ids = list(dict.fromkeys(payload.evidence_event_ids))

    # Validate that every referenced alert exists.
    alerts = list(
        db.scalars(
            select(Alert).where(Alert.event_id.in_(event_ids))
        ).all()
    ) if event_ids else []

    found_ids = {alert.event_id for alert in alerts}
    missing_ids = set(event_ids) - found_ids

    if missing_ids:
        raise HTTPException(
            status_code=404,
            detail={
                "message": "One or more evidence alerts were not found.",
                "missing_event_ids": sorted(missing_ids),
            },
        )

    incident = Incident(
        incident_id=incident_id,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        risk_score=payload.risk_score,
        risk_level=payload.risk_level,
        status="Open",
        assigned_to=payload.assigned_to,
        created_at=now,
        updated_at=now,
    )

    try:
        db.add(incident)

        for event_id in event_ids:
            db.add(
                IncidentEvidence(
                    evidence_id=str(uuid4()),
                    incident_id=incident_id,
                    event_id=event_id,
                    evidence_type="alert",
                    explanation="Alert attached during incident creation.",
                    created_at=now,
                )
            )

        db.add(
            IncidentTimeline(
                timeline_id=str(uuid4()),
                incident_id=incident_id,
                action="incident_created",
                details=f"Incident created with {len(event_ids)} evidence alert(s).",
                actor="system",
                created_at=now,
            )
        )

        db.commit()
        db.refresh(incident)

    except Exception:
        db.rollback()
        raise

    return incident



@app.get("/api/incidents", response_model=list[IncidentOut])
def list_incidents(
    status: IncidentStatus | None = None,
    severity: Severity | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    statement = select(Incident)

    if status is not None:
        statement = statement.where(Incident.status == status)

    if severity is not None:
        statement = statement.where(Incident.severity == severity)

    statement = (
        statement
        .order_by(Incident.created_at.desc())
        .limit(limit)
        .offset(offset)
    )

    return list(db.scalars(statement).all())



@app.get(
    "/api/incidents/{incident_id}",
    response_model=IncidentOut,
)
def get_incident(
    incident_id: str,
    db: Session = Depends(get_db),
):
    incident = db.get(Incident, incident_id)

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found.",
        )

    # Load related records before returning the response.
    _ = incident.evidence
    _ = incident.timeline

    return incident




@app.patch(
    "/api/incidents/{incident_id}/status",
    response_model=IncidentOut,
)
def update_incident_status(
    incident_id: str,
    payload: IncidentStatusUpdate,
    db: Session = Depends(get_db),
):
    incident = db.get(Incident, incident_id)

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found.",
        )

    allowed_transitions = {
        "Open": {"Investigating"},
        "Investigating": {"Resolved"},
        "Resolved": {"Closed"},
        "Closed": set(),
    }

    current_status = incident.status

    if payload.status not in allowed_transitions.get(current_status, set()):
        raise HTTPException(
            status_code=409,
            detail=f"Invalid incident status transition: {current_status} -> {payload.status}",
        )

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    try:
        incident.status = payload.status
        incident.updated_at = now

        db.add(
            IncidentTimeline(
                timeline_id=str(uuid4()),
                incident_id=incident_id,
                action="status_changed",
                details=(
                    f"{current_status} -> {payload.status}. "
                    f"{payload.details}"
                ),
                actor=payload.actor,
                created_at=now,
            )
        )

        db.commit()
        db.refresh(incident)

    except Exception:
        db.rollback()
        raise

    return incident


@app.post("/api/alerts", response_model=AlertOut, status_code=201)
def create_alert(payload: AlertCreate, db: Session = Depends(get_db)):
    event = Alert(
        event_id=f"MANUAL-{uuid4().hex[:12].upper()}",
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        source_type="manual",
        **payload.model_dump(),
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    return event



LAB_NETWORKS = {
    "USER": ipaddress.ip_network("192.168.10.0/24"),
    "SERVER": ipaddress.ip_network("192.168.20.0/24"),
    "DMZ": ipaddress.ip_network("192.168.30.0/24"),
    "MANAGEMENT": ipaddress.ip_network("192.168.40.0/24"),
    "TELEMETRY": ipaddress.ip_network("192.168.56.0/24"),
}

PFSENSE_INTERFACE_ZONES = {
    "em0": "WAN",
    "em1": "USER",
    "em2": "SERVER",
    "em3": "DMZ",
    "em4": "MANAGEMENT",
    "em5": "TELEMETRY",
    "opt1": "SERVER",
    "opt2": "DMZ",
    "opt3": "MANAGEMENT",
    "opt4": "TELEMETRY",
}


def classify_pfsense_interface(interface: str) -> str:
    """Map a pfSense interface identifier to its ZTShield zone."""
    return PFSENSE_INTERFACE_ZONES.get(
        interface.strip().lower(),
        interface.strip().upper(),
    )

def classify_network_zone(source_ip: str, destination_ip: str) -> str:
    """Classify an event using the configured ZTShield lab subnets."""

    for address in (source_ip, destination_ip):
        parsed_address = ipaddress.ip_address(address)

        for zone, network in LAB_NETWORKS.items():
            if (
                parsed_address.version == network.version
                and parsed_address in network
            ):
                return zone

    return "UNKNOWN"



@app.post(
    "/api/ingest/suricata",
    response_model=AlertOut,
    status_code=201,
)
def ingest_suricata_event(
    payload: SuricataEveInput,
    capture_mode: Literal["live", "pcap", "unknown"] = Header(
        default="unknown",
        alias="X-ZTShield-Capture-Mode",
    ),
    db: Session = Depends(get_db),
    _: None = Depends(verify_ingest_token),
):
    # Accept only Suricata alert events.
    if payload.event_type.casefold() != "alert":
        raise HTTPException(
            status_code=422,
            detail="Only Suricata EVE alert events are accepted.",
        )

    if payload.alert is None:
        raise HTTPException(
            status_code=422,
            detail="The EVE alert object is required.",
        )

    # Validate and normalize the IP addresses.
    try:
        source_address = ipaddress.ip_address(payload.src_ip)
        destination_address = ipaddress.ip_address(payload.dest_ip)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail="The source or destination IP address is invalid.",
        ) from exc

    signature = payload.alert.signature.strip()
    if not signature:
        raise HTTPException(
            status_code=422,
            detail="The alert signature cannot be empty.",
        )

    # Lower number means greater severity in Suricata.
    severity_map = {
        1: "Critical",
        2: "High",
        3: "Medium",
        4: "Low",
    }
    severity = severity_map[payload.alert.severity]

    # Parse the event time, or use current UTC if it is absent.
    if payload.timestamp:
        try:
            parsed_time = datetime.fromisoformat(
                payload.timestamp.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail="The EVE timestamp must be a valid ISO timestamp.",
            ) from exc

        if parsed_time.tzinfo is None:
            parsed_time = parsed_time.replace(tzinfo=timezone.utc)

        timestamp = parsed_time.astimezone(timezone.utc).isoformat(
            timespec="seconds"
        )
    else:
        timestamp = datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        )

    # Include the destination port when available.
    destination = str(destination_address)

    if payload.dest_port is not None:
        if destination_address.version == 6:
            destination = f"[{destination}]:{payload.dest_port}"
        else:
            destination = f"{destination}:{payload.dest_port}"
            
    source_type = {
    "live": "suricata_live",
    "pcap": "suricata_pcap",
    "unknown": "suricata",
    }[capture_mode]

    event = Alert(
        event_id=f"SURICATA-{uuid4().hex[:12].upper()}",
        timestamp=timestamp,
        title=signature,
        source_ip=str(source_address),
        destination=destination,
        protocol=payload.proto.upper(),
        zone=classify_network_zone(
            str(source_address),
            str(destination_address),
        ),
        severity=severity,
        status="New",
        source_type=source_type,
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    return event


@app.post(
    "/api/ingest/pfsense",
    response_model=AlertOut,
    status_code=201,
)
def ingest_pfsense_event(
    payload: PfsenseFilterLogInput,
    x_event_fingerprint: str = Header(..., min_length=64, max_length=64),
    db: Session = Depends(get_db),
    _: None = Depends(verify_ingest_token),
):
    # Validate and normalize IP addresses.
    try:
        source_address = ipaddress.ip_address(payload.src_ip)
        destination_address = ipaddress.ip_address(payload.dest_ip)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail="Invalid source or destination IP address.",
        ) from exc

    # Ensure the supplied IP version matches the actual addresses.
    if (
        source_address.version != payload.ip_version
        or destination_address.version != payload.ip_version
    ):
        raise HTTPException(
            status_code=422,
            detail="IP version does not match the supplied addresses.",
        )

    # Normalize the timestamp to UTC.
    try:
        parsed_time = datetime.fromisoformat(
            payload.timestamp.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail="Invalid pfSense event timestamp.",
        ) from exc

    if parsed_time.tzinfo is None:
        parsed_time = parsed_time.replace(tzinfo=timezone.utc)

    timestamp = parsed_time.astimezone(timezone.utc).isoformat(
        timespec="seconds"
    )

    protocol = payload.protocol.upper()

    # Include destination port when available.
    destination = str(destination_address)

    if payload.dest_port is not None:
        if destination_address.version == 6:
            destination = f"[{destination}]:{payload.dest_port}"
        else:
            destination = f"{destination}:{payload.dest_port}"

    # Deterministic ID prevents duplicate ingestion of identical events.
    fingerprint = x_event_fingerprint.strip().upper()
    
    if not all(c in "0123456789ABCDEF" for c in fingerprint):
        raise HTTPException(
            status_code=422,
            detail="Invalid event fingerprint.",
        )

    event_id = f"PFSENSE-{fingerprint[:32]}"

    existing_event = db.get(Alert, event_id)

    if existing_event is not None:
        return existing_event

    event = Alert(
        event_id=event_id,
        timestamp=timestamp,
        title=(
            f"pfSense {payload.action.upper()} "
            f"{protocol} on {payload.interface}"
        ),
        source_ip=str(source_address),
        destination=destination,
        protocol=protocol,
        zone=classify_pfsense_interface(payload.interface),
        severity=payload.severity.title(),
        status="New",
        source_type="pfsense_live",
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    return event



@app.get("/api/summary")
def get_summary(db: Session = Depends(get_db)):
    alerts = list(db.scalars(select(Alert)).all())

    # Count telemetry source types with an event in the last five minutes.
    now = datetime.now(timezone.utc)
    lookback = timedelta(minutes=5)

    live_source_types = {
        "suricata_live",
        "pfsense_live",
        "wireguard_live",
        "tpot_live",
    }

    active_sources = set()

    for alert in alerts:
        if alert.source_type not in live_source_types:
            continue

        try:
            event_time = datetime.fromisoformat(
                alert.timestamp.replace("Z", "+00:00")
            )

            if event_time.tzinfo is None:
                event_time = event_time.replace(tzinfo=timezone.utc)

            event_time = event_time.astimezone(timezone.utc)
            age = now - event_time

            if timedelta(0) <= age <= lookback:
                active_sources.add(alert.source_type)

        except (ValueError, TypeError):
            continue

    return {
        "total_alerts": len(alerts),
        "by_severity": {
            severity: sum(
                alert.severity == severity for alert in alerts
            )
            for severity in ["Critical", "High", "Medium", "Low", "Info"]
        },
        "demo_events": sum(
            alert.source_type == "demo" for alert in alerts
        ),
        "non_demo_events": sum(
            alert.source_type != "demo" for alert in alerts
        ),
        "connected_sensors": len(active_sources),
        "recent_live_sources": len(active_sources),
        "recent_activity_window_seconds": 300,
    }

@app.get("/api/sensors")
def get_sensors(db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    lookback = timedelta(minutes=5)

    sensor_definitions = [
        {
            "id": "suricata",
            "name": "Suricata IDS/IPS",
            "source_type": "suricata_live",
            "description": "Live network intrusion-detection events",
        },
        {
            "id": "pfsense",
            "name": "pfSense Firewall",
            "source_type": "pfsense_live",
            "description": "Firewall and inter-zone policy events",
        },
        {
            "id": "wireguard",
            "name": "WireGuard VPN",
            "source_type": "wireguard_live",
            "description": "Secure remote-access telemetry",
        },
        {
            "id": "tpot",
            "name": "T-Pot Honeypot",
            "source_type": "tpot_live",
            "description": "Honeypot and captured-activity events",
        },
    ]

    alerts = list(db.scalars(select(Alert)).all())
    results = []

    for sensor in sensor_definitions:
        latest_time = None

        for alert in alerts:
            if alert.source_type != sensor["source_type"]:
                continue

            try:
                event_time = datetime.fromisoformat(
                    alert.timestamp.replace("Z", "+00:00")
                )

                if event_time.tzinfo is None:
                    event_time = event_time.replace(
                        tzinfo=timezone.utc
                    )

                event_time = event_time.astimezone(timezone.utc)

            except (ValueError, TypeError):
                continue

            # Ignore future-dated events when determining sensor activity.
            if event_time > now:
                continue

            if latest_time is None or event_time > latest_time:
                latest_time = event_time

        last_seen = None
        seconds_since_last_event = None

        if latest_time is not None:
            age = now - latest_time
            seconds_since_last_event = max(
                0, int(age.total_seconds())
            )
            last_seen = latest_time.isoformat(timespec="seconds")

        if (
            latest_time is not None
            and timedelta(0) <= now - latest_time <= lookback
        ):
            status = "recently_active"
        elif latest_time is not None:
            status = "no_recent_events"
        else:
            status = "not_integrated"

        results.append(
            {
                **sensor,
                "status": status,
                "last_seen": last_seen,
                "seconds_since_last_event": seconds_since_last_event,
            }
        )

    return {
        "activity_window_seconds": 300,
        "sensors": results,
    }


