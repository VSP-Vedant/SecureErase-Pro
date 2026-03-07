"""
Tests: CryptoUtils
Covers: encrypt/decrypt roundtrip, tamper detection, IP hashing, API key generation
"""
import os
import pytest

os.environ["COLUMN_ENCRYPTION_KEY"] = "a" * 64  # 32-byte key as 64 hex chars
os.environ["IP_HASH_SALT"] = "test-salt"

from portal.backend.modules.crypto_utils import (
    encrypt_column, decrypt_column, hash_ip, hash_api_key,
    generate_api_key, canonical_json, sha256_hex
)
from cryptography.exceptions import InvalidTag


def test_encrypt_decrypt_roundtrip():
    plaintext = "sensitive data: /etc/secret/path"
    blob = encrypt_column(plaintext)
    assert blob != plaintext
    recovered = decrypt_column(blob)
    assert recovered == plaintext


def test_different_nonce_each_call():
    p = "same plaintext"
    b1 = encrypt_column(p)
    b2 = encrypt_column(p)
    assert b1 != b2  # different nonces produce different ciphertexts


def test_tamper_detection():
    blob = encrypt_column("test data")
    # Corrupt a byte in the middle
    data = list(blob)
    idx = len(data) // 2
    data[idx] = 'X' if data[idx] != 'X' else 'Y'
    corrupted = "".join(data)
    with pytest.raises(Exception):  # InvalidTag or similar
        decrypt_column(corrupted)


def test_hash_ip_deterministic():
    h1 = hash_ip("192.168.1.1")
    h2 = hash_ip("192.168.1.1")
    assert h1 == h2


def test_hash_ip_different_for_different_ips():
    assert hash_ip("192.168.1.1") != hash_ip("10.0.0.1")


def test_generate_api_key():
    raw, key_hash = generate_api_key()
    assert raw.startswith("sep_v1_")
    assert len(key_hash) == 64
    assert hash_api_key(raw) == key_hash


def test_canonical_json_removes_sig_value():
    cert = {
        "certificate_id": "abc",
        "signature": {"value": "SHOULD_BE_REMOVED", "algorithm": "RS4096-PSS-SHA256"},
    }
    result = canonical_json(cert)
    parsed = __import__("json").loads(result)
    assert parsed["signature"]["value"] == ""


def test_canonical_json_sorted_keys():
    cert = {"z": 1, "a": 2, "m": 3, "signature": {"value": ""}}
    result = canonical_json(cert)
    # Keys should be sorted
    assert result.index(b"a") < result.index(b"m") < result.index(b"z")