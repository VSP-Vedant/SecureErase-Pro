"""
=============================================================================
Module: IDLookupHandler
Purpose: Resolve a certificate ID against the registry, fetch the matching
         public key, and orchestrate the full verification pipeline.
         This is the handler for GET /api/v1/verify/{cert_id}.
Inputs:  cert_id (UUID string), access tier, SQLAlchemy session
Outputs: VerificationResult with tier-appropriate data
Dependencies: modules/registry_service.py, modules/verification_engine.py
Security:
  - UUID format validated before any DB query
  - Public key fetched from registry — not trusted from external sources
  - Revocation checked before signature verification
=============================================================================
"""

import json
import uuid
from typing import Optional

from sqlalchemy.orm import Session

from .models import Certificate, PublicKey
from .registry_service import (
    CertificateNotFound,
    get_certificate_enterprise,
    get_certificate_public,
    get_public_key_pem,
)
from .verification_engine import (
    VerificationResult,
    VerificationStatus,
    verify_certificate,
)


class LookupError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


def _parse_cert_id(cert_id_str: str) -> uuid.UUID:
    """Validate and parse UUID. Raises LookupError on invalid format."""
    try:
        return uuid.UUID(str(cert_id_str))
    except (ValueError, AttributeError):
        raise LookupError(f"Invalid certificate ID format: {cert_id_str}", 400)


def lookup_and_verify(
    cert_id_str: str,
    session: Session,
    tier: str = "public",
) -> dict:
    """
    Full lookup-and-verify pipeline for a certificate ID.

    Steps:
    1. Validate UUID format
    2. Fetch certificate from registry
    3. Check revocation status
    4. Fetch issuer's public key from registry
    5. Reconstruct cert dict for verification
    6. Run VerificationEngine
    7. Return tier-appropriate response

    Args:
        cert_id_str: Certificate ID as string
        session: SQLAlchemy session
        tier: "public" | "enterprise" | "admin"

    Returns:
        dict with keys: status, message, certificate (tier-filtered), verified_at
    """
    cert_id = _parse_cert_id(cert_id_str)

    # Fetch from registry
    cert_row = session.get(Certificate, cert_id)
    if not cert_row:
        return _build_response(
            VerificationResult(
                status=VerificationStatus.NOT_FOUND,
                certificate_id=str(cert_id),
                message=f"Certificate {cert_id} is not registered in this portal",
            ),
            tier=tier,
            cert_data=None,
        )

    # Check revocation before signature verification
    if cert_row.revoked:
        revocation_info = None
        if cert_row.revocation:
            revocation_info = {
                "revoked_at": cert_row.revocation.revoked_at.isoformat(),
                "reason": cert_row.revocation.reason,
            }
        return _build_response(
            VerificationResult(
                status=VerificationStatus.REVOKED,
                certificate_id=str(cert_id),
                message="Certificate has been revoked",
                public_data={"revocation": revocation_info},
            ),
            tier=tier,
            cert_data=None,
        )

    # Fetch public key from registry
    public_key_pem = get_public_key_pem(cert_row.public_key_fingerprint, session)
    if not public_key_pem:
        return _build_response(
            VerificationResult(
                status=VerificationStatus.ERROR,
                certificate_id=str(cert_id),
                message=(
                    f"Public key {cert_row.public_key_fingerprint[:16]}... "
                    f"not found in portal registry. "
                    f"Offline verification is still possible using the issuer's published key."
                ),
            ),
            tier=tier,
            cert_data=None,
        )

    # Reconstruct minimal cert dict for signature verification
    # We use the stored signature_value + public non-encrypted fields
    # For full verification we need the full cert — enterprise tier gets this
    # from decrypted data; public tier verifies against stored signature only.
    cert_dict_for_verify = _reconstruct_cert_dict(cert_row, session, tier)

    # Run verification
    result = verify_certificate(cert_dict_for_verify, public_key_pem)

    # Get tier-appropriate data
    if tier in ("enterprise", "admin"):
        cert_data = get_certificate_enterprise(cert_id, session)
    else:
        cert_data = get_certificate_public(cert_id, session)

    return _build_response(result, tier=tier, cert_data=cert_data)


def _reconstruct_cert_dict(cert_row: Certificate, session: Session, tier: str) -> dict:
    """
    Reconstruct a certificate dict from stored (and decrypted) data
    for use with VerificationEngine.
    """
    from .crypto_utils import decrypt_column

    operator = {}
    target = {}
    pass_detail = []
    compliance_detail = []

    if cert_row.operator_encrypted:
        try:
            operator = json.loads(decrypt_column(cert_row.operator_encrypted))
        except Exception:
            pass
    if cert_row.target_encrypted:
        try:
            target = json.loads(decrypt_column(cert_row.target_encrypted))
        except Exception:
            pass
    if cert_row.pass_detail_encrypted:
        try:
            pass_detail = json.loads(decrypt_column(cert_row.pass_detail_encrypted))
        except Exception:
            pass
    if cert_row.compliance_detail_encrypted:
        try:
            compliance_detail = json.loads(
                decrypt_column(cert_row.compliance_detail_encrypted)
            )
        except Exception:
            pass

    return {
        "certificate_id": str(cert_row.id),
        "schema_version": cert_row.schema_version,
        "issuer": {
            "organization": cert_row.issuer_org,
            "portal_verification_url": cert_row.portal_verification_url,
            "public_key_url": f"/api/v1/keys/{cert_row.public_key_fingerprint}",
            "public_key_fingerprint": cert_row.public_key_fingerprint,
        },
        "generated_at": cert_row.generated_at.isoformat().replace("+00:00", "Z"),
        "operator": operator,
        "target": {
            **target,
            "sha256_before": cert_row.sha256_before,
            "sha3_256_before": cert_row.sha3_256_before,
        },
        "wipe_operation": {
            "standard_applied": cert_row.wipe_standard,
            "passes_completed": cert_row.passes_completed,
            "pass_detail": pass_detail,
            "duration_seconds": cert_row.duration_seconds or 0,
            "verified": cert_row.verified,
            "sha256_after": cert_row.sha256_after,
            "sha3_256_after": cert_row.sha3_256_after,
        },
        "compliance_mapping": compliance_detail,
        "registry": {
            "registered": True,
            "registry_url": cert_row.portal_verification_url,
            "registered_at": cert_row.registered_at.isoformat().replace("+00:00", "Z"),
        },
        "audit_chain": {
            "previous_certificate_hash": cert_row.previous_certificate_hash or "GENESIS",
            "chain_position": cert_row.chain_position or 1,
        },
        "signature": {
            "algorithm": cert_row.signature_algorithm,
            "public_key_fingerprint": cert_row.public_key_fingerprint,
            "signed_at": cert_row.generated_at.isoformat().replace("+00:00", "Z"),
            "value": cert_row.signature_value,
        },
    }


def _build_response(result: VerificationResult, tier: str,
                     cert_data: Optional[dict]) -> dict:
    """Build the final API response dict from a VerificationResult."""
    from datetime import datetime, timezone
    response = {
        "status": result.status.value,
        "message": result.message,
        "certificate_id": result.certificate_id,
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }
    if result.algorithm:
        response["algorithm"] = result.algorithm
    if result.tamper_details:
        response["tamper_details"] = result.tamper_details
    if cert_data:
        response["certificate"] = cert_data
    elif result.public_data:
        response["certificate"] = result.public_data
    return response
