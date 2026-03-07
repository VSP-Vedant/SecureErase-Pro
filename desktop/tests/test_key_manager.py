"""
Tests: KeyManager
Covers: key generation (RSA-4096, ECDSA-P384), persistence, fingerprint
        computation, PEM export, and key loading.
"""
import os
import sys
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from desktop.modules.key_manager import KeyManager, KeyType, KeyPairInfo


@pytest.fixture
def km(tmp_path):
    return KeyManager(key_store_dir=str(tmp_path))


def test_generate_rsa_keypair(km):
    info = km.generate_keypair(KeyType.RSA_4096)
    assert isinstance(info, KeyPairInfo)
    assert info.key_type == "RSA-4096"


def test_generate_ecdsa_keypair(km):
    info = km.generate_keypair(KeyType.ECDSA_P384)
    assert isinstance(info, KeyPairInfo)
    assert info.key_type == "ECDSA-P384"


def test_keypair_info_has_fingerprint(km):
    info = km.generate_keypair(KeyType.RSA_4096)
    assert len(info.fingerprint) == 64
    assert all(c in "0123456789abcdef" for c in info.fingerprint)


def test_keypair_info_has_public_key_pem(km):
    info = km.generate_keypair(KeyType.RSA_4096)
    assert b"BEGIN PUBLIC KEY" in info.public_key_pem


def test_keypair_info_has_private_key_path(km):
    info = km.generate_keypair(KeyType.RSA_4096)
    assert info.private_key_path is not None
    assert os.path.exists(info.private_key_path)


def test_private_key_file_permissions(km):
    info = km.generate_keypair(KeyType.RSA_4096)
    mode = oct(os.stat(info.private_key_path).st_mode & 0o777)
    assert mode == oct(0o600)


def test_export_public_key_pem(km):
    km.generate_keypair(KeyType.RSA_4096)
    pem = km.export_public_key_pem()
    assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")


def test_different_keypairs_have_different_fingerprints(km):
    info1 = km.generate_keypair(KeyType.RSA_4096, key_name="key1")
    info2 = km.generate_keypair(KeyType.RSA_4096, key_name="key2")
    assert info1.fingerprint != info2.fingerprint


def test_rsa_and_ecdsa_fingerprints_are_both_valid(km):
    rsa = km.generate_keypair(KeyType.RSA_4096)
    ecdsa = km.generate_keypair(KeyType.ECDSA_P384)
    assert len(rsa.fingerprint) == 64
    assert len(ecdsa.fingerprint) == 64
