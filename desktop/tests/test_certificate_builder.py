"""
Tests: CertificateBuilder
"""
import sys, os, uuid, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from desktop.modules.certificate_builder import build_certificate, canonical_serialize


def _sample_inputs():
    return {
        "file_entry": {
            "path": "/tmp/test.txt", "type": "file", "size_bytes": 1024,
            "file_count": 1,
        },
        "wipe_result": {
            "standard_applied": "DoD 5220.22-M (3-pass)",
            "passes_completed": 3,
            "pass_detail": [
                {"pass_number": i, "pattern": p, "verified": True}
                for i, p in enumerate(["0x00","0xFF","random"], 1)
            ],
            "duration_seconds": 5.2,
            "verified": True,
            "sha256_after": "c"*64,
            "sha3_256_after": "d"*64,
        },
        "hash_before": {"sha256": "a"*64, "sha3_256": "b"*64},
        "compliance_mappings": [
            {"standard": "GDPR", "version": "2018", "control_reference": "Art.17",
             "satisfied": True, "notes": ""},
        ],
        "operator": {
            "username": "admin", "hostname": "ws01", "ip_address": "10.0.0.1",
            "os": "Windows 11", "app_version": "0.1.0",
        },
        "issuer_org": "Test Corp",
        "portal_url": "https://verify.test.com",
        "public_key_fingerprint": "e"*64,
        "public_key_url": "https://verify.test.com/keys/e"*1,
    }


def test_certificate_has_required_fields():
    inputs = _sample_inputs()
    cert = build_certificate(**inputs)
    for field in ["certificate_id", "schema_version", "issuer", "generated_at",
                   "operator", "target", "wipe_operation", "compliance_mapping",
                   "registry", "audit_chain", "signature"]:
        assert field in cert, f"Missing field: {field}"


def test_certificate_id_is_valid_uuid():
    cert = build_certificate(**_sample_inputs())
    uuid.UUID(cert["certificate_id"])  # raises if invalid


def test_canonical_serialize_consistent():
    cert = build_certificate(**_sample_inputs())
    b1 = canonical_serialize(cert)
    b2 = canonical_serialize(cert)
    assert b1 == b2


def test_canonical_serialize_clears_signature_value():
    cert = build_certificate(**_sample_inputs())
    cert["signature"]["value"] = "SHOULD_BE_GONE"
    canonical = canonical_serialize(cert)
    parsed = json.loads(canonical)
    assert parsed["signature"]["value"] == ""