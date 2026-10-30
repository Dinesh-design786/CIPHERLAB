from datetime import datetime, timezone
from pathlib import Path
import os
from sqlalchemy import (
    create_engine,
    String,
    Integer,
    Float,
    DateTime,
    ForeignKey,
    Text,
    Boolean,
    Index,
    inspect,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

BASE = Path(__file__).resolve().parents[1]
DATA = Path(os.getenv("APP_DATA_DIR", BASE / "data"))
DATA.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    f"sqlite:///{DATA / 'signatures.db'}", connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(bind=engine, autoflush=False)


def now():
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class User(Base):
    """User account entity (reserved for future multi-user auth)."""
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class PublicKey(Base):
    """
    Public key registry with encrypted private key material at rest (AES-256-GCM + scrypt).
    Includes lifecycle status (active, revoked, retired).
    """
    __tablename__ = "public_keys"
    id: Mapped[int] = mapped_column(primary_key=True)
    label: Mapped[str] = mapped_column(String(160))
    p: Mapped[str] = mapped_column(Text)
    g: Mapped[str] = mapped_column(Text)
    y: Mapped[str] = mapped_column(Text)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    encrypted_private: Mapped[str] = mapped_column(Text)
    salt: Mapped[str] = mapped_column(String(64))
    nonce: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(20), default="active")  # 'active', 'revoked', 'retired'
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Document(Base):
    """Document metadata and local storage record."""
    __tablename__ = "documents"
    id: Mapped[int] = mapped_column(primary_key=True)
    storage_id: Mapped[str] = mapped_column(String(36), unique=True)
    filename: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    size: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Signature(Base):
    """Detached ElGamal signature record."""
    __tablename__ = "signatures"
    id: Mapped[int] = mapped_column(primary_key=True)
    document_id: Mapped[int] = mapped_column(ForeignKey("documents.id"))
    key_id: Mapped[int] = mapped_column(ForeignKey("public_keys.id"))
    r: Mapped[str] = mapped_column(Text)
    s: Mapped[str] = mapped_column(Text)
    package_version: Mapped[str] = mapped_column(String(16), default="1.0")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class VerificationEvent(Base):
    """Verification log table (maintained for existing API & test compatibility)."""
    __tablename__ = "verification_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    filename: Mapped[str] = mapped_column(String(255))
    result: Mapped[bool] = mapped_column(Boolean, index=True)
    reason_code: Mapped[str] = mapped_column(String(64))
    digest: Mapped[str] = mapped_column(String(64))
    fingerprint: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


Index("ix_verification_created_result", VerificationEvent.created_at, VerificationEvent.result)


class AuditEvent(Base):
    """
    Comprehensive, immutable audit ledger for all cryptographic and key events.
    Never stores plaintext secrets, passphrases, or nonces.
    """
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    event_type: Mapped[str] = mapped_column(String(32), index=True)  # 'SIGNING', 'VERIFICATION', 'KEY_GEN', 'KEY_REVOKE', 'KEY_ROTATE', 'KEY_EXPORT', 'KEY_IMPORT'
    filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result: Mapped[str] = mapped_column(String(32), index=True)  # 'SUCCESS', 'VALID', 'TAMPERED', 'INVALID', 'ERROR'
    reason_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)  # Non-sensitive JSON details
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


Index("ix_audit_events_created", AuditEvent.created_at)
Index("ix_audit_events_type_result", AuditEvent.event_type, AuditEvent.result)


class BenchmarkRecord(Base):
    """Repeatable benchmark and performance test execution records."""
    __tablename__ = "benchmark_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    file_size_bytes: Mapped[int] = mapped_column(Integer)
    file_size_label: Mapped[str] = mapped_column(String(20))
    hash_time_ms: Mapped[float] = mapped_column(Float)
    sign_time_ms: Mapped[float] = mapped_column(Float)
    verify_time_ms: Mapped[float] = mapped_column(Float)
    valid_pass: Mapped[bool] = mapped_column(Boolean)
    tamper_detected: Mapped[bool] = mapped_column(Boolean)
    repetitions: Mapped[int] = mapped_column(Integer, default=1)
    environment_info: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


# Create all tables
Base.metadata.create_all(engine)

# Auto-migrate existing SQLite columns if missing
try:
    with engine.connect() as conn:
        cols = [c["name"] for c in inspect(engine).get_columns("public_keys")]
        if "status" not in cols:
            conn.execute(text("ALTER TABLE public_keys ADD COLUMN status VARCHAR(20) DEFAULT 'active'"))
        if "revoked_at" not in cols:
            conn.execute(text("ALTER TABLE public_keys ADD COLUMN revoked_at DATETIME"))
        if "revocation_reason" not in cols:
            conn.execute(text("ALTER TABLE public_keys ADD COLUMN revocation_reason VARCHAR(255)"))
        conn.commit()
except Exception:
    pass
