"""
Tests: DigitalSigner
Covers: RSA-4096 and ECDSA-P384 signing, verification, tamper detection,
        and cross-key rejection.
"""
import os
import sys
import base64
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from desktop.modules.digital_signer import DigitalSigner
from desktop.modules.key_manager import KeyManager, KeyType


@pytest.fixture
def rsa_key(tmp_path):
    km = KeyManager(key_store_dir=str(tmp_path))
    info = km.generate_keypair(KeyType.RSA_4096)
    return info


@pytest.fixture
def ecdsa_key(tmp_path):
    km = KeyManager(key_store_dir=str(tmp_path / "ecdsa"))
    info = km.generate_keypair(KeyType.ECDSA_P384)
    return info


@pytest.fixture
def signer():
    return DigitalSigner()


@pytest.fixture
def sample_cert():
    return {
        "certificate_id": "test-uuid-1234",
        "schema_version": "1.0",
        "generated_at": "2025-01-01T00:00:00+00:00",
        "wipe_operation": {"standard_applied": "DoD 5220.22-M (3-pass)", "verified": True},
        "signature": {"algorithm": "", "public_key_fingerprint": "", "signed_at": "", "value": ""},
    }


# ── RSA-4096 ──────────────────────────────────────────────────────────────────

def test_rsa_sign_returns_signature(signer, rsa_key, sample_cert):
    signed = signer.sign(cert=sample_cert, private_key_path=rsa_key.private_key_path)
    assert signed["signature"]["value"] != ""
    assert signed["signature"]["algorithm"].startswith("RS")


def test_rsa_verify_valid(signer, rsa_key, sample_cert):
    signed = signer.sign(cert=sample_cert, private_key_path=rsa_key.private_key_path)
    assert signer.verify(cert=signed, public_key_pem=rsa_key.public_key_pem) is True


def test_rsa_tamper_detection(signer, rsa_key, sample_cert):
    signed = signer.sign(cert=sample_cert, private_key_path=rsa_key.private_key_path)
    signed["generated_at"] = "2099-01-01T00:00:00+00:00"  # tamper
    assert signer.verify(cert=signed, public_key_pem=rsa_key.public_key_pem) is False


def test_rsa_signature_value_is_base64url(signer, rsa_key, sample_cert):
    signed = signer.sign(cert=sample_cert, private_key_path=rsa_key.private_key_path)
    val = signed["signature"]["value"]
    padded = val + "=" * (-len(val) % 4)
    decoded = base64.urlsafe_b64decode(padded)
    assert len(decoded) > 0


# ── ECDSA-P384 ────────────────────────────────────────────────────────────────

def test_ecdsa_sign_returns_signature(signer, ecdsa_key, sample_cert):
    signed = signer.sign(cert=sample_cert, private_key_path=ecdsa_key.private_key_path)
    assert signed["signature"]["value"] != ""
    assert "ECDSA" in signed["signature"]["algorithm"]


def test_ecdsa_verify_valid(signer, ecdsa_key, sample_cert):
    signed = signer.sign(cert=sample_cert, private_key_path=ecdsa_key.private_key_path)
    assert signer.verify(cert=signed, public_key_pem=ecdsa_key.public_key_pem) is True


def test_ecdsa_tamper_detection(signer, ecdsa_key, sample_cert):
    signed = signer.sign(cert=sample_cert, private_key_path=ecdsa_key.private_key_path)
    signed["schema_version"] = "9.9"  # tamper
    assert signer.verify(cert=signed, public_key_pem=ecdsa_key.public_key_pem) is False


# ── Cross-key rejection ───────────────────────────────────────────────────────

def test_wrong_key_fails_verification(signer, tmp_path, sample_cert):
    km1 = KeyManager(key_store_dir=str(tmp_path / "km1"))
    km2 = KeyManager(key_store_dir=str(tmp_path / "km2"))
    info1 = km1.generate_keypair(KeyType.RSA_4096, key_name="k1")
    info2 = km2.generate_keypair(KeyType.RSA_4096, key_name="k2")
    signed = signer.sign(cert=sample_cert, private_key_path=info1.private_key_path)
    assert signer.verify(cert=signed, public_key_pem=info2.public_key_pem) is False


# ── Signature block structure ─────────────────────────────────────────────────

def test_signature_block_has_all_fields(signer, rsa_key, sample_cert):
    signed = signer.sign(cert=sample_cert, private_key_path=rsa_key.private_key_path)
    sig = signed["signature"]
    for field in ("algorithm", "public_key_fingerprint", "signed_at", "value"):
        assert field in sig, f"Missing signature field: {field}"
