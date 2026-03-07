"""
=============================================================================
Module: CryptoUtils
Purpose: Shared cryptographic utilities for the verification portal.
         Provides AES-256-GCM encryption/decryption for sensitive columns,
         SHA-256 hashing for IP anonymisation and API key storage,
         and canonical JSON serialisation matching the desktop app.
Inputs:  plaintext data, encryption key from environment
Outputs: encrypted blobs (base64), hashes, canonical JSON bytes
Dependencies: cryptography, os, base64, json, hashlib
Security:
  - AES-256-GCM with random 96-bit nonce per operation
  - Nonce prepended to ciphertext before base64 encoding
  - Tag verified on decryption — any tampering raises InvalidTag
  - Encryption key loaded once from COLUMN_ENCRYPTION_KEY env var
=============================================================================
"""

import base64
import hashlib
import json
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _get_column_key() -> bytes:
    """Load the 32-byte AES column encryption key from environment."""
    raw = os.environ.get("COLUMN_ENCRYPTION_KEY", "")
    if not raw:
        raise RuntimeError("COLUMN_ENCRYPTION_KEY environment variable not set")
    key_bytes = bytes.fromhex(raw)
    if len(key_bytes) != 32:
        raise ValueError("COLUMN_ENCRYPTION_KEY must be 32 bytes (64 hex chars)")
    return key_bytes


def encrypt_column(plaintext: str) -> str:
    """
    Encrypt a string value for storage in a sensitive database column.
    Returns base64url-encoded nonce||ciphertext||tag.
    """
    key = _get_column_key()
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)  # 96-bit random nonce
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    # Pack: nonce (12 bytes) | ciphertext+tag
    packed = nonce + ciphertext_with_tag
    return base64.urlsafe_b64encode(packed).decode("ascii")


def decrypt_column(blob: str) -> str:
    """
    Decrypt a base64url-encoded encrypted column value.
    Raises cryptography.exceptions.InvalidTag on tampering.
    """
    key = _get_column_key()
    aesgcm = AESGCM(key)
    packed = base64.urlsafe_b64decode(blob.encode("ascii"))
    nonce = packed[:12]
    ciphertext_with_tag = packed[12:]
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    return plaintext_bytes.decode("utf-8")


def hash_ip(ip_address: str) -> str:
    """
    One-way hash of an IP address for privacy-preserving storage.
    GDPR: raw IPs are personal data; hashed IPs are pseudonymous.
    Returns SHA-256 hex string.
    """
    ip_salt = os.environ.get("IP_HASH_SALT", "secureerase-default-salt")
    salted = f"{ip_salt}:{ip_address}"
    return hashlib.sha256(salted.encode("utf-8")).hexdigest()


def hash_api_key(raw_key: str) -> str:
    """SHA-256 hex of a raw API key for storage. Raw key never persisted."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def canonical_json(cert_dict: dict) -> bytes:
    """
    Produce canonical JSON bytes matching the desktop app's signing format.
    Step 1: Set signature.value to empty string (as during signing)
    Step 2: json.dumps with sort_keys=True, no whitespace, ensure_ascii=True
    Step 3: Encode as UTF-8
    This MUST match desktop/modules/certificate_builder.py canonical_serialize().
    """
    import copy
    d = copy.deepcopy(cert_dict)
    if "signature" in d and "value" in d["signature"]:
        d["signature"]["value"] = ""
    return json.dumps(d, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate_api_key() -> tuple[str, str]:
    """
    Generate a new API key.
    Returns (raw_key, key_hash) — raw_key shown once to user, never stored.
    Format: sep_v1_{32 random hex bytes}
    """
    raw = "sep_v1_" + secrets.token_hex(32)
    return raw, hash_api_key(raw)
