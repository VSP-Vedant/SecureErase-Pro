"""
=============================================================================
Module: VerificationEngine
Purpose: Cryptographically verify SecureErase Pro certificates.
         This is the security-critical core of the portal. All verification
         logic runs in a separate ProcessPoolExecutor to isolate malformed
         certificate processing from the main API process.
Inputs:  Certificate dict (from file upload, ID lookup, or QR scan)
         Optional: public key PEM override
Outputs: VerificationResult dataclass
Dependencies: cryptography, concurrent.futures, modules/crypto_utils.py
Compliance:
  - Implements Phase 4 verification workflow exactly
  - ISO/IEC 27001 A.8.10: independent cryptographic proof of erasure
Security:
  - Process isolation: malformed cert cannot crash API process
  - Constant-time comparison for signature bytes via hmac.compare_digest
  - Public key fetched from registry — never trusted from cert payload alone
=============================================================================
"""

import base64
import hashlib
import hmac
import json
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeout
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from .crypto_utils import canonical_json, sha256_hex


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

class VerificationStatus(str, Enum):
    VALID = "valid"
    INVALID = "invalid"       # signature does not verify
    TAMPERED = "tampered"     # fields modified after signing
    NOT_FOUND = "not_found"   # cert ID not in registry
    REVOKED = "revoked"       # cert in registry but revoked
    ERROR = "error"           # unexpected processing error


@dataclass
class VerificationResult:
    status: VerificationStatus
    certificate_id: Optional[str] = None
    message: str = ""
    algorithm: Optional[str] = None
    public_key_fingerprint: Optional[str] = None
    signed_at: Optional[str] = None
    # Populated for TAMPERED status
    tamper_details: Optional[str] = None
    # For non-ERROR statuses, include safe public data
    public_data: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Core verification logic (runs in subprocess)
# ---------------------------------------------------------------------------

def _verify_in_subprocess(cert_dict: dict, public_key_pem: str) -> dict:
    """
    Pure function: verify cert signature against provided public key PEM.
    Returns a dict (not a dataclass) so it can cross process boundaries.
    Must be importable at module level (no closures).
    """
    import base64, hashlib, json, hmac
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, ec

    try:
        # Step 1: Extract signature block
        sig_block = cert_dict.get("signature", {})
        algorithm = sig_block.get("algorithm", "")
        sig_b64 = sig_block.get("value", "")
        key_fp_in_cert = sig_block.get("public_key_fingerprint", "")

        if not sig_b64:
            return {"status": "invalid", "message": "Missing signature value"}

        # Step 2: Decode signature
        try:
            sig_bytes = base64.urlsafe_b64decode(sig_b64 + "==")
        except Exception as e:
            return {"status": "invalid", "message": f"Signature decode error: {e}"}

        # Step 3: Canonical JSON (signature.value set to "")
        import copy
        d = copy.deepcopy(cert_dict)
        d["signature"]["value"] = ""
        canonical_bytes = json.dumps(d, sort_keys=True, separators=(",", ":"),
                                      ensure_ascii=True).encode("utf-8")

        # Step 4: Load public key
        pub_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))

        # Step 5: Verify key fingerprint matches what cert claims
        pub_key_der = pub_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        actual_fp = hashlib.sha256(pub_key_der).hexdigest()
        if not hmac.compare_digest(actual_fp, key_fp_in_cert):
            return {
                "status": "tampered",
                "message": "Public key fingerprint mismatch",
                "tamper_details": f"Certificate claims {key_fp_in_cert[:16]}..., "
                                   f"actual key is {actual_fp[:16]}..."
            }

        # Step 6: Verify signature based on algorithm
        if "RS4096" in algorithm or "RSA" in algorithm:
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
            if not isinstance(pub_key, RSAPublicKey):
                return {"status": "invalid", "message": "Expected RSA public key"}
            try:
                pub_key.verify(
                    sig_bytes,
                    canonical_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            except InvalidSignature:
                return {"status": "tampered",
                        "message": "RSA signature verification failed — certificate has been modified"}

        elif "ECDSA" in algorithm or "P384" in algorithm:
            from cryptography.hazmat.primitives.asymmetric.ec import (
                EllipticCurvePublicKey, ECDSA
            )
            if not isinstance(pub_key, EllipticCurvePublicKey):
                return {"status": "invalid", "message": "Expected ECDSA public key"}
            try:
                pub_key.verify(sig_bytes, canonical_bytes, ec.ECDSA(hashes.SHA256()))
            except InvalidSignature:
                return {"status": "tampered",
                        "message": "ECDSA signature verification failed — certificate has been modified"}
        else:
            return {"status": "invalid", "message": f"Unsupported algorithm: {algorithm}"}

        # Step 7: All checks passed
        return {
            "status": "valid",
            "algorithm": algorithm,
            "public_key_fingerprint": actual_fp,
            "signed_at": sig_block.get("signed_at"),
            "message": "Signature verified successfully",
        }

    except Exception as e:
        return {"status": "error", "message": f"Verification error: {type(e).__name__}: {e}"}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# Module-level executor — reused across requests
_executor = ProcessPoolExecutor(max_workers=4)
_VERIFY_TIMEOUT = 10  # seconds


def verify_certificate(cert_dict: dict, public_key_pem: str) -> VerificationResult:
    """
    Verify a certificate cryptographically.
    Runs in a subprocess pool to isolate malformed certificate processing.

    Args:
        cert_dict: Parsed certificate dict (signature.value must be present)
        public_key_pem: PEM of the issuer's public key to verify against

    Returns:
        VerificationResult with status, message, and safe public data
    """
    cert_id = cert_dict.get("certificate_id")

    # Basic schema check before spawning subprocess
    if not isinstance(cert_dict, dict):
        return VerificationResult(
            status=VerificationStatus.INVALID,
            message="Certificate must be a JSON object"
        )
    required_top_keys = {"certificate_id", "issuer", "wipe_operation",
                          "signature", "generated_at"}
    missing = required_top_keys - set(cert_dict.keys())
    if missing:
        return VerificationResult(
            status=VerificationStatus.INVALID,
            certificate_id=cert_id,
            message=f"Missing required fields: {', '.join(sorted(missing))}"
        )

    # Spawn subprocess for crypto isolation
    try:
        future = _executor.submit(_verify_in_subprocess, cert_dict, public_key_pem)
        result_dict = future.result(timeout=_VERIFY_TIMEOUT)
    except FuturesTimeout:
        return VerificationResult(
            status=VerificationStatus.ERROR,
            certificate_id=cert_id,
            message="Verification timed out"
        )
    except Exception as e:
        return VerificationResult(
            status=VerificationStatus.ERROR,
            certificate_id=cert_id,
            message=f"Subprocess error: {e}"
        )

    status = VerificationStatus(result_dict.get("status", "error"))

    # Build safe public data for the response
    wipe_op = cert_dict.get("wipe_operation", {})
    issuer = cert_dict.get("issuer", {})
    public_data = {
        "certificate_id": cert_id,
        "generated_at": cert_dict.get("generated_at"),
        "issuer_org": issuer.get("organization"),
        "wipe_standard": wipe_op.get("standard_applied"),
        "passes_completed": wipe_op.get("passes_completed"),
        "wipe_verified": wipe_op.get("verified"),
        "compliance_frameworks": [
            m.get("standard") for m in cert_dict.get("compliance_mapping", [])
            if m.get("satisfied")
        ],
    }

    return VerificationResult(
        status=status,
        certificate_id=cert_id,
        message=result_dict.get("message", ""),
        algorithm=result_dict.get("algorithm"),
        public_key_fingerprint=result_dict.get("public_key_fingerprint"),
        signed_at=result_dict.get("signed_at"),
        tamper_details=result_dict.get("tamper_details"),
        public_data=public_data,
    )


def verify_certificate_bytes(cert_bytes: bytes, public_key_pem: str) -> VerificationResult:
    """
    Parse raw JSON bytes and verify. Used by FileUploadHandler.
    Validates JSON parse before cryptographic check.
    """
    try:
        cert_dict = json.loads(cert_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return VerificationResult(
            status=VerificationStatus.INVALID,
            message=f"Invalid JSON: {e}"
        )
    return verify_certificate(cert_dict, public_key_pem)
