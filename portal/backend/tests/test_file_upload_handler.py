"""
Tests: FileUploadHandler
Covers: valid upload, oversized, wrong type, schema violations, fingerprint mismatch
"""
import json
import uuid
import pytest
from portal.backend.modules.file_upload_handler import (
    parse_and_validate_certificate, UploadValidationError, MAX_FILE_SIZE
)


def _minimal_cert(overrides=None):
    fp = "a" * 64
    cert = {
        "certificate_id": str(uuid.uuid4()),
        "schema_version": "1.0",
        "issuer": {
            "organization": "Test",
            "portal_verification_url": "https://test.com/cert/abc",
            "public_key_url": "https://test.com/keys/x",
            "public_key_fingerprint": fp,
        },
        "generated_at": "2025-01-15T10:00:00Z",
        "operator": {"username": "u", "hostname": "h", "ip_address": "1.2.3.4",
                      "os": "Linux", "app_version": "1.0.0"},
        "target": {"path": "/tmp/f.txt", "type": "file", "size_bytes": 100, "file_count": 1,
                    "sha256_before": "a"*64, "sha3_256_before": "b"*64},
        "wipe_operation": {
            "standard_applied": "NIST SP 800-88", "passes_completed": 1,
            "pass_detail": [{"pass_number": 1, "pattern": "0x00", "verified": True}],
            "duration_seconds": 1.0, "verified": True,
            "sha256_after": "c"*64, "sha3_256_after": "d"*64,
        },
        "compliance_mapping": [
            {"standard": "GDPR", "version": "2018", "control_reference": "Art.17",
             "satisfied": True, "notes": ""},
        ],
        "registry": {"registered": False, "registry_url": "", "registered_at": ""},
        "audit_chain": {"previous_certificate_hash": "GENESIS", "chain_position": 1},
        "signature": {
            "algorithm": "RS4096-PSS-SHA256",
            "public_key_fingerprint": fp,
            "signed_at": "2025-01-15T10:00:00Z",
            "value": "dGVzdA==",
        },
    }
    if overrides:
        cert.update(overrides)
    return cert


def test_valid_upload():
    cert = _minimal_cert()
    raw, validated = parse_and_validate_certificate(
        json.dumps(cert).encode(), "application/json"
    )
    assert str(validated.certificate_id) == cert["certificate_id"]


def test_file_too_large():
    cert = _minimal_cert()
    big_bytes = json.dumps(cert).encode() + b"x" * MAX_FILE_SIZE
    with pytest.raises(UploadValidationError, match="too large"):
        parse_and_validate_certificate(big_bytes)


def test_empty_file():
    with pytest.raises(UploadValidationError, match="Empty"):
        parse_and_validate_certificate(b"")


def test_invalid_json():
    with pytest.raises(UploadValidationError, match="Invalid JSON"):
        parse_and_validate_certificate(b"not json {{", "application/json")


def test_missing_certificate_id():
    cert = _minimal_cert()
    del cert["certificate_id"]
    with pytest.raises(UploadValidationError):
        parse_and_validate_certificate(json.dumps(cert).encode())


def test_fingerprint_mismatch():
    cert = _minimal_cert()
    cert["signature"]["public_key_fingerprint"] = "b" * 64  # differs from issuer
    with pytest.raises(UploadValidationError, match="fingerprint"):
        parse_and_validate_certificate(json.dumps(cert).encode())


def test_invalid_algorithm():
    cert = _minimal_cert()
    cert["signature"]["algorithm"] = "MD5-BROKEN"
    with pytest.raises(UploadValidationError):
        parse_and_validate_certificate(json.dumps(cert).encode())