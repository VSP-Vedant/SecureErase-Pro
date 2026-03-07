"""
=============================================================================
Module: Database Models
Purpose: SQLAlchemy ORM models for the SecureErase Pro verification portal.
         Tables: certificates, verification_events, public_keys,
                 api_keys, users, revocations.
Dependencies: sqlalchemy, psycopg2-binary, alembic
Compliance:
  - ISO/IEC 27001 A.8.10: audit trail via verification_events
  - GDPR Art.5(1)(e): encrypted columns for operator/path data
  - SOC 2 CC6.5: complete disposal records in certificates table
=============================================================================
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Enum, Float, ForeignKey,
    Index, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, relationship


def utcnow():
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Certificate(Base):
    __tablename__ = "certificates"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
                comment="UUID v4 matching certificate_id in signed JSON")
    schema_version = Column(String(16), nullable=False, default="1.0")

    issuer_org = Column(String(256), nullable=False)
    portal_verification_url = Column(Text, nullable=False)
    public_key_fingerprint = Column(String(64), nullable=False, index=True)

    generated_at = Column(DateTime(timezone=True), nullable=False)
    registered_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)

    # Non-sensitive — public tier
    wipe_standard = Column(String(128), nullable=False)
    passes_completed = Column(Integer, nullable=False)
    verified = Column(Boolean, nullable=False)
    duration_seconds = Column(Float, nullable=True)
    sha256_before = Column(String(64), nullable=True)
    sha3_256_before = Column(String(64), nullable=True)
    sha256_after = Column(String(64), nullable=True)
    sha3_256_after = Column(String(64), nullable=True)
    compliance_frameworks = Column(JSONB, nullable=False, default=list)

    signature_algorithm = Column(String(32), nullable=False)
    signature_value = Column(Text, nullable=False)

    # AES-256-GCM encrypted blobs — enterprise tier only
    operator_encrypted = Column(Text, nullable=True)
    target_encrypted = Column(Text, nullable=True)
    pass_detail_encrypted = Column(Text, nullable=True)
    compliance_detail_encrypted = Column(Text, nullable=True)

    # Audit chain
    previous_certificate_hash = Column(String(64), nullable=True)
    chain_position = Column(Integer, nullable=True)

    revoked = Column(Boolean, nullable=False, default=False)

    verifications = relationship("VerificationEvent", back_populates="certificate",
                                  cascade="all, delete-orphan")
    revocation = relationship("Revocation", back_populates="certificate",
                               uselist=False, cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_certificates_wipe_standard", "wipe_standard"),
        Index("ix_certificates_generated_at", "generated_at"),
        Index("ix_certificates_revoked", "revoked"),
    )


class VerificationEvent(Base):
    __tablename__ = "verification_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    certificate_id = Column(UUID(as_uuid=True),
                             ForeignKey("certificates.id", ondelete="CASCADE"),
                             nullable=True)
    verified_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    result = Column(Enum("valid", "invalid", "tampered", "not_found", "revoked",
                          name="verification_result_enum"), nullable=False)
    method = Column(Enum("file_upload", "id_lookup", "qr_scan",
                          name="verification_method_enum"), nullable=False)
    tier = Column(Enum("public", "enterprise", "admin",
                        name="access_tier_enum"), nullable=False, default="public")
    ip_hash = Column(String(64), nullable=True,
                      comment="SHA-256 of client IP — raw IP never stored")
    user_id = Column(UUID(as_uuid=True),
                      ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    flagged = Column(Boolean, nullable=False, default=False)
    flag_reason = Column(Text, nullable=True)

    certificate = relationship("Certificate", back_populates="verifications")
    user = relationship("User", back_populates="verification_events")

    __table_args__ = (
        Index("ix_ve_certificate_id", "certificate_id"),
        Index("ix_ve_verified_at", "verified_at"),
        Index("ix_ve_result", "result"),
        Index("ix_ve_flagged", "flagged"),
    )


class PublicKey(Base):
    __tablename__ = "public_keys"

    fingerprint = Column(String(64), primary_key=True,
                          comment="SHA-256 hex of public key DER")
    pem = Column(Text, nullable=False)
    issuer_org = Column(String(256), nullable=False)
    algorithm = Column(String(32), nullable=False)
    active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    rotated_at = Column(DateTime(timezone=True), nullable=True)
    notes = Column(Text, nullable=True)


class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key_hash = Column(String(64), nullable=False, unique=True,
                       comment="SHA-256 hex of raw API key — raw key never stored")
    key_prefix = Column(String(8), nullable=False)
    label = Column(String(256), nullable=False)
    org_id = Column(String(256), nullable=True)
    tier = Column(Enum("enterprise", "admin", name="api_key_tier_enum"),
                  nullable=False, default="enterprise")
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    revoked = Column(Boolean, nullable=False, default=False)
    created_by_user_id = Column(UUID(as_uuid=True),
                                 ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    created_by = relationship("User", back_populates="api_keys")

    __table_args__ = (
        Index("ix_api_keys_key_hash", "key_hash"),
        Index("ix_api_keys_revoked", "revoked"),
    )


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(320), nullable=False, unique=True, index=True)
    password_hash = Column(String(128), nullable=True,
                            comment="bcrypt hash; NULL for SSO-only accounts")
    display_name = Column(String(256), nullable=True)
    org_id = Column(String(256), nullable=True)
    role = Column(Enum("enterprise", "admin", name="user_role_enum"),
                  nullable=False, default="enterprise")
    totp_secret_encrypted = Column(Text, nullable=True)
    mfa_enabled = Column(Boolean, nullable=False, default=False)
    sso_provider = Column(String(64), nullable=True)
    sso_subject = Column(String(256), nullable=True)
    active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    api_keys = relationship("APIKey", back_populates="created_by")
    verification_events = relationship("VerificationEvent", back_populates="user")

    __table_args__ = (
        UniqueConstraint("sso_provider", "sso_subject", name="uq_users_sso"),
    )


class Revocation(Base):
    __tablename__ = "revocations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    certificate_id = Column(UUID(as_uuid=True),
                             ForeignKey("certificates.id", ondelete="CASCADE"),
                             nullable=False, unique=True)
    revoked_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    revoked_by_user_id = Column(UUID(as_uuid=True),
                                 ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reason = Column(Text, nullable=False)

    certificate = relationship("Certificate", back_populates="revocation")
    revoked_by = relationship("User")
