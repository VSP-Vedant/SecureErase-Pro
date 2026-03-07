"""
Tests: QRDecodeHandler
Covers: valid deep-link URL, bare UUID, invalid payload, wrong format
"""
import pytest
from portal.backend.modules.qr_decode_handler import (
    extract_cert_id_from_payload, QRDecodeError
)

VALID_UUID = "550e8400-e29b-41d4-a716-446655440000"
VALID_URL = f"https://verify.example.com/cert/{VALID_UUID}"


def test_extract_from_full_url():
    assert extract_cert_id_from_payload(VALID_URL) == VALID_UUID.lower()


def test_extract_from_url_with_trailing_slash():
    assert extract_cert_id_from_payload(VALID_URL + "/") == VALID_UUID.lower()


def test_extract_bare_uuid():
    assert extract_cert_id_from_payload(VALID_UUID) == VALID_UUID.lower()


def test_extract_uuid_uppercase():
    assert extract_cert_id_from_payload(VALID_UUID.upper()) == VALID_UUID.lower()


def test_invalid_payload_plain_text():
    with pytest.raises(QRDecodeError):
        extract_cert_id_from_payload("this is not a cert URL")


def test_empty_payload():
    with pytest.raises(QRDecodeError):
        extract_cert_id_from_payload("")


def test_none_payload():
    with pytest.raises(QRDecodeError):
        extract_cert_id_from_payload(None)


def test_uuid_version_not_4():
    # UUID with version 1 — should be rejected (not v4)
    uuid_v1 = "550e8400-e29b-11d4-a716-446655440000"
    url = f"https://verify.example.com/cert/{uuid_v1}"
    with pytest.raises(QRDecodeError):
        extract_cert_id_from_payload(url)