"""
Tests: SSDHandler
Covers: SSDEraseResult structure, media type detection, dry-run safety,
        and NIST SP 800-88 SSD limitation documentation.
"""
import os
import sys
import json
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from desktop.modules.ssd_handler import SSDHandler, SSDEraseResult, SSDEraseMethod


@pytest.fixture
def handler():
    return SSDHandler()


def test_ssd_erase_result_has_required_fields():
    """SSDEraseResult has all certificate-required fields."""
    result = SSDEraseResult(
        method=SSDEraseMethod.CRYPTO_KEY_DELETION,
        device_path="/dev/sda",
        command_issued="crypto-erase key-1",
        firmware_response="success",
        success=True,
        duration_seconds=1.5,
        performed_at="2025-01-01T00:00:00+00:00",
        key_id_deleted="key-abc-123",
    )
    assert result.method == SSDEraseMethod.CRYPTO_KEY_DELETION
    assert result.success is True
    assert result.duration_seconds == 1.5


def test_erase_result_is_json_serializable():
    """SSDEraseResult can be serialized for inclusion in a certificate."""
    from dataclasses import asdict
    result = SSDEraseResult(
        method=SSDEraseMethod.NVME_FORMAT_CRYPTO,
        device_path="/dev/nvme0",
        command_issued="nvme format --ses=2 /dev/nvme0",
        firmware_response="Format successful",
        success=True,
        duration_seconds=2.3,
        performed_at="2025-01-01T00:00:00+00:00",
    )
    d = asdict(result)
    serialized = json.dumps(d)
    assert "nvme" in serialized.lower() or "NVMe" in serialized


def test_detect_device_type_returns_dict(handler):
    """detect_device_type returns a dict with 'type' key."""
    result = handler.detect_device_type("/tmp")
    assert isinstance(result, dict)
    assert "type" in result
    assert result["type"] in ("SSD", "NVMe", "HDD", "unknown")


def test_ssd_erase_method_has_ata_and_nvme():
    """SSDEraseMethod enum contains ATA and NVMe variants."""
    methods = [e for e in SSDEraseMethod]
    assert SSDEraseMethod.ATA_SECURE_ERASE in methods
    assert SSDEraseMethod.NVME_FORMAT_CRYPTO in methods


def test_ata_secure_erase_fails_gracefully_on_non_device(handler):
    """ata_secure_erase on a non-device path returns a failed SSDEraseResult."""
    try:
        result = handler.ata_secure_erase(device="/tmp/not_a_device")
        # If it returns a result (error path), check it's the right type
        assert isinstance(result, SSDEraseResult)
        assert result.success is False
    except RuntimeError as e:
        # RuntimeError is acceptable when hdparm is not installed in CI
        assert "hdparm" in str(e) or "tool" in str(e).lower()


def test_compliance_note_is_present_in_result():
    """
    NIST SP 800-88 Rev.1 compliance note must appear in SSDEraseResult.
    This ensures the certificate records the SSD limitation warning.
    """
    result = SSDEraseResult(
        method=SSDEraseMethod.ATA_SECURE_ERASE,
        device_path="/dev/sda",
        command_issued="hdparm --security-erase /dev/sda",
        firmware_response="success",
        success=True,
        duration_seconds=30.0,
        performed_at="2025-01-01T00:00:00+00:00",
    )
    # compliance_note is a class-level default on SSDEraseResult
    assert hasattr(result, "compliance_note")
    assert "NIST" in result.compliance_note or "800-88" in result.compliance_note
