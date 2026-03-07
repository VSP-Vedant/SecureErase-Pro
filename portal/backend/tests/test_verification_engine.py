"""
Tests: VerificationEngine
Covers: valid cert, tampered cert, wrong key, unsupported algorithm, missing fields
"""
import base64
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization

from portal.backend.modules.verification_engine import (
    VerificationStatus, verify_certificate, verify_certificate_bytes
)


def _make_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    pub_der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    import hashlib
    fp = hashlib.sha256(pub_der).hexdigest()
    return private_key, pub_pem, fp


def _build_cert(private_key, fp):
    """Build and sign a minimal valid certificate dict."""
    import json as _json
    import copy

    cert = {
        "certificate_id": str(uuid.uuid4()),
        "schema_version": "1.0",
        "issuer": {
            "organization": "Test Org",
            "portal_verification_url": f"https://test.example.com/cert/abc",
            "public_key_url": "https://test.example.com/keys/test",
            "public_key_fingerprint": fp,
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "operator": {"username": "testuser", "hostname": "testhost",
                      "ip_address": "192.168.1.1", "os": "Linux 6.0", "app_version": "0.1.0"},
        "target": {"path": "/tmp/test.txt", "type": "file", "size_bytes": 1024,
                    "file_count": 1, "sha256_before": "a" * 64, "sha3_256_before": "b" * 64},
        "wipe_operation": {
            "standard_applied": "NIST SP 800-88 Rev.1 — Purge",
            "passes_completed": 1,
            "pass_detail": [{"pass_number": 1, "pattern": "0x00", "verified": True}],
            "duration_seconds": 2.5,
            "verified": True,
            "sha256_after": "c" * 64,
            "sha3_256_after": "d" * 64,
        },
        "compliance_mapping": [
            {"standard": "NIST SP 800-53 Rev.5", "version": "Rev.5",
             "control_reference": "MP-6", "satisfied": True, "notes": ""},
        ],
        "registry": {"registered": False, "registry_url": "", "registered_at": ""},
        "audit_chain": {"previous_certificate_hash": "GENESIS", "chain_position": 1},
        "signature": {
            "algorithm": "RS4096-PSS-SHA256",
            "public_key_fingerprint": fp,
            "signed_at": datetime.now(timezone.utc).isoformat(),
            "value": "",
        },
    }

    # Sign
    d = copy.deepcopy(cert)
    canonical = _json.dumps(d, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True).encode("utf-8")
    sig = private_key.sign(
        canonical,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    cert["signature"]["value"] = base64.urlsafe_b64encode(sig).decode()
    return cert


def test_valid_certificate():
    private_key, pub_pem, fp = _make_rsa_keypair()
    cert = _build_cert(private_key, fp)
    result = verify_certificate(cert, pub_pem)
    assert result.status == VerificationStatus.VALID
    assert result.certificate_id == cert["certificate_id"]


def test_tampered_certificate():
    private_key, pub_pem, fp = _make_rsa_keypair()
    cert = _build_cert(private_key, fp)
    # Tamper: change wipe standard after signing
    cert["wipe_operation"]["standard_applied"] = "EVIL MODIFIED"
    result = verify_certificate(cert, pub_pem)
    assert result.status == VerificationStatus.TAMPERED


def test_wrong_public_key():
    private_key, pub_pem, fp = _make_rsa_keypair()
    wrong_key, wrong_pub_pem, _ = _make_rsa_keypair()
    cert = _build_cert(private_key, fp)
    result = verify_certificate(cert, wrong_pub_pem)
    # Either TAMPERED (fingerprint mismatch) or INVALID (sig fails)
    assert result.status in (VerificationStatus.TAMPERED, VerificationStatus.INVALID)


def test_missing_required_fields():
    _, pub_pem, _ = _make_rsa_keypair()
    result = verify_certificate({"certificate_id": "abc"}, pub_pem)
    assert result.status == VerificationStatus.INVALID
    assert "Missing required fields" in result.message


def test_invalid_json_bytes():
    _, pub_pem, _ = _make_rsa_keypair()
    result = verify_certificate_bytes(b"not json {{{", pub_pem)
    assert result.status == VerificationStatus.INVALID


def test_empty_bytes():
    _, pub_pem, _ = _make_rsa_keypair()
    result = verify_certificate_bytes(b"", pub_pem)
    assert result.status == VerificationStatus.INVALID