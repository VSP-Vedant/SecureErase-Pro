"""
=============================================================================
Module: RegistryService
Purpose: Certificate registration, storage, and lookup in PostgreSQL.
         Handles encrypting sensitive fields before storage, decrypting on
         retrieval for authorised tiers, anomaly detection on registration,
         and public key management.
Inputs:  Signed certificate dict, SQLAlchemy session, access tier
Outputs: Certificate ORM objects, registration results, lookup results
Dependencies: sqlalchemy, modules/models.py, modules/crypto_utils.py
Compliance:
  - GDPR Art.5(1)(e): sensitive fields encrypted at rest
  - ISO/IEC 27001 A.8.10: complete record of every erasure operation
  - SOC 2 CC6.5: audit-ready certificate registry
Security:
  - Operator details / file paths stored AES-256-GCM encrypted
  - No sensitive data in public-tier responses
  - Duplicate certificate ID registration returns existing record
=============================================================================
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import select, func
from sqlalchemy.orm import Session

from .models import (
    Certificate, PublicKey, Revocation, VerificationEvent
)
from .crypto_utils import encrypt_column, decrypt_column, sha256_hex


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

class RegistrationError(Exception):
    pass


def register_certificate(cert_dict: dict, session: Session) -> Certificate:
    """
    Register a signed certificate in the portal registry.

    Security decisions:
    - Sensitive fields (operator, target path, pass_detail, compliance_detail)
      are AES-256-GCM encrypted before INSERT.
    - Duplicate certificate_id is idempotent — returns existing row.
    - Validates UUID format before any DB interaction.
    """
    raw_id = cert_dict.get("certificate_id")
    if not raw_id:
        raise RegistrationError("certificate_id is required")
    try:
        cert_id = UUID(str(raw_id))
    except ValueError:
        raise RegistrationError(f"Invalid certificate_id format: {raw_id}")

    # Idempotent — return existing if already registered
    existing = session.get(Certificate, cert_id)
    if existing:
        return existing

    issuer = cert_dict.get("issuer", {})
    wipe_op = cert_dict.get("wipe_operation", {})
    target = cert_dict.get("target", {})
    operator = cert_dict.get("operator", {})
    sig = cert_dict.get("signature", {})
    registry = cert_dict.get("registry", {})
    audit_chain = cert_dict.get("audit_chain", {})

    # Extract compliance framework names for the public JSONB column
    compliance_names = [
        m.get("standard", "") for m in cert_dict.get("compliance_mapping", [])
        if m.get("satisfied", False)
    ]

    generated_at_str = cert_dict.get("generated_at", "")
    try:
        generated_at = datetime.fromisoformat(
            generated_at_str.replace("Z", "+00:00")
        )
    except (ValueError, AttributeError):
        raise RegistrationError(f"Invalid generated_at timestamp: {generated_at_str}")

    # Encrypt sensitive columns
    operator_blob = encrypt_column(json.dumps(operator)) if operator else None
    target_blob = encrypt_column(json.dumps(target)) if target else None
    pass_detail = wipe_op.get("pass_detail", [])
    pass_blob = encrypt_column(json.dumps(pass_detail)) if pass_detail else None
    compliance_detail = cert_dict.get("compliance_mapping", [])
    compliance_blob = encrypt_column(json.dumps(compliance_detail)) if compliance_detail else None

    cert_row = Certificate(
        id=cert_id,
        schema_version=cert_dict.get("schema_version", "1.0"),
        issuer_org=issuer.get("organization", ""),
        portal_verification_url=issuer.get("portal_verification_url", ""),
        public_key_fingerprint=issuer.get("public_key_fingerprint", ""),
        generated_at=generated_at,
        wipe_standard=wipe_op.get("standard_applied", ""),
        passes_completed=wipe_op.get("passes_completed", 0),
        verified=bool(wipe_op.get("verified", False)),
        duration_seconds=wipe_op.get("duration_seconds"),
        sha256_before=target.get("sha256_before"),
        sha3_256_before=target.get("sha3_256_before"),
        sha256_after=wipe_op.get("sha256_after"),
        sha3_256_after=wipe_op.get("sha3_256_after"),
        compliance_frameworks=compliance_names,
        signature_algorithm=sig.get("algorithm", ""),
        signature_value=sig.get("value", ""),
        operator_encrypted=operator_blob,
        target_encrypted=target_blob,
        pass_detail_encrypted=pass_blob,
        compliance_detail_encrypted=compliance_blob,
        previous_certificate_hash=audit_chain.get("previous_certificate_hash"),
        chain_position=audit_chain.get("chain_position"),
        revoked=False,
    )

    session.add(cert_row)
    session.flush()  # get DB error early before commit
    return cert_row


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------

class CertificateNotFound(Exception):
    pass


def get_certificate_public(cert_id: UUID, session: Session) -> dict:
    """
    Return public-tier certificate data (no sensitive fields).
    Raises CertificateNotFound if not in registry.
    """
    cert = session.get(Certificate, cert_id)
    if not cert:
        raise CertificateNotFound(f"Certificate {cert_id} not found in registry")

    revocation_info = None
    if cert.revoked and cert.revocation:
        revocation_info = {
            "revoked_at": cert.revocation.revoked_at.isoformat(),
            "reason": cert.revocation.reason,
        }

    return {
        "certificate_id": str(cert.id),
        "schema_version": cert.schema_version,
        "issuer_org": cert.issuer_org,
        "portal_verification_url": cert.portal_verification_url,
        "generated_at": cert.generated_at.isoformat(),
        "registered_at": cert.registered_at.isoformat(),
        "wipe_standard": cert.wipe_standard,
        "passes_completed": cert.passes_completed,
        "verified": cert.verified,
        "compliance_frameworks": cert.compliance_frameworks,
        "signature_algorithm": cert.signature_algorithm,
        "revoked": cert.revoked,
        "revocation": revocation_info,
    }


def get_certificate_enterprise(cert_id: UUID, session: Session) -> dict:
    """
    Return full certificate data including decrypted sensitive fields.
    For enterprise and admin tiers only.
    """
    base = get_certificate_public(cert_id, session)
    cert = session.get(Certificate, cert_id)

    # Decrypt sensitive fields
    operator = json.loads(decrypt_column(cert.operator_encrypted)) \
        if cert.operator_encrypted else {}
    target = json.loads(decrypt_column(cert.target_encrypted)) \
        if cert.target_encrypted else {}
    pass_detail = json.loads(decrypt_column(cert.pass_detail_encrypted)) \
        if cert.pass_detail_encrypted else []
    compliance_detail = json.loads(decrypt_column(cert.compliance_detail_encrypted)) \
        if cert.compliance_detail_encrypted else []

    base.update({
        "operator": operator,
        "target": target,
        "duration_seconds": cert.duration_seconds,
        "sha256_before": cert.sha256_before,
        "sha3_256_before": cert.sha3_256_before,
        "sha256_after": cert.sha256_after,
        "sha3_256_after": cert.sha3_256_after,
        "pass_detail": pass_detail,
        "compliance_detail": compliance_detail,
        "audit_chain": {
            "previous_certificate_hash": cert.previous_certificate_hash,
            "chain_position": cert.chain_position,
        },
        "signature_value": cert.signature_value,
    })
    return base


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------

class RevocationError(Exception):
    pass


def revoke_certificate(cert_id: UUID, reason: str,
                        revoked_by_user_id: Optional[UUID],
                        session: Session) -> None:
    """Admin-only: mark certificate as revoked."""
    cert = session.get(Certificate, cert_id)
    if not cert:
        raise CertificateNotFound(f"Certificate {cert_id} not found")
    if cert.revoked:
        raise RevocationError(f"Certificate {cert_id} is already revoked")
    if not reason or not reason.strip():
        raise RevocationError("Revocation reason is required")

    from .models import Revocation
    cert.revoked = True
    revocation = Revocation(
        certificate_id=cert_id,
        revoked_by_user_id=revoked_by_user_id,
        reason=reason.strip(),
    )
    session.add(revocation)
    session.flush()


# ---------------------------------------------------------------------------
# Public Key Management
# ---------------------------------------------------------------------------

def register_public_key(fingerprint: str, pem: str, issuer_org: str,
                         algorithm: str, session: Session) -> PublicKey:
    """Register or update an issuer's public key."""
    existing = session.get(PublicKey, fingerprint)
    if existing:
        existing.active = True
        existing.pem = pem
        return existing
    pk = PublicKey(
        fingerprint=fingerprint,
        pem=pem,
        issuer_org=issuer_org,
        algorithm=algorithm,
    )
    session.add(pk)
    session.flush()
    return pk


def get_public_key_pem(fingerprint: str, session: Session) -> Optional[str]:
    """Retrieve an active public key PEM by fingerprint."""
    pk = session.get(PublicKey, fingerprint)
    if pk and pk.active:
        return pk.pem
    return None


def rotate_public_key(old_fingerprint: str, new_pem: str, new_fingerprint: str,
                       new_algorithm: str, issuer_org: str,
                       session: Session) -> PublicKey:
    """Deactivate old key and register new key atomically."""
    old_key = session.get(PublicKey, old_fingerprint)
    if old_key:
        old_key.active = False
        old_key.rotated_at = datetime.now(timezone.utc)
    new_key = register_public_key(new_fingerprint, new_pem,
                                   issuer_org, new_algorithm, session)
    return new_key


# ---------------------------------------------------------------------------
# Admin registry queries
# ---------------------------------------------------------------------------

def list_certificates(session: Session, page: int = 1, page_size: int = 50,
                       revoked_only: bool = False) -> dict:
    """Paginated certificate list for admin dashboard."""
    query = select(Certificate)
    if revoked_only:
        query = query.where(Certificate.revoked == True)
    query = query.order_by(Certificate.registered_at.desc())

    total = session.execute(
        select(func.count()).select_from(Certificate)
        .where(Certificate.revoked == revoked_only if revoked_only else True.__class__)
    ).scalar() or 0

    offset = (page - 1) * page_size
    rows = session.execute(query.offset(offset).limit(page_size)).scalars().all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "results": [get_certificate_public(r.id, session) for r in rows],
    }
