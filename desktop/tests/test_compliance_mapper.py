"""
Tests: ComplianceMapper
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from desktop.modules.compliance_mapper import map_to_frameworks, STANDARDS


def test_nist_maps_to_expected_frameworks():
    mappings = map_to_frameworks("NIST SP 800-88 Rev.1 - Purge", "hdd", "general")
    names = [m["standard"] for m in mappings]
    assert "NIST SP 800-53 Rev.5" in names
    assert "ISO/IEC 27001:2022" in names


def test_all_standards_produce_non_empty_mapping():
    for std in STANDARDS:
        result = map_to_frameworks(std, "hdd", "general")
        assert len(result) > 0, f"No mappings for standard: {std}"


def test_gdpr_included_for_all_standards():
    for std in STANDARDS:
        result = map_to_frameworks(std, "hdd", "personal_data")
        names = [m["standard"] for m in result]
        assert "GDPR" in names, f"GDPR missing for {std}"


def test_unknown_standard_returns_empty():
    result = map_to_frameworks("TOTALLY_FAKE_STANDARD_XYZ", "hdd", "general")
    assert result == []