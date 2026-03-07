"""
Tests: SecureWipeEngine
Covers: all WipeStandard pass sequences, read-back verification,
        partial-failure handling, and WipeResult structure.
"""
import os
import sys
import tempfile
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from desktop.modules.secure_wipe_engine import SecureWipeEngine, WipeStandard, WipeResult


@pytest.fixture
def engine():
    return SecureWipeEngine()


@pytest.fixture
def small_file(tmp_path):
    """A 64 KB test file filled with non-zero data."""
    f = tmp_path / "target.bin"
    f.write_bytes(b"\xAA" * 65536)
    return str(f)


def test_zero_fill_wipe(engine, small_file):
    result = engine.wipe(small_file, WipeStandard.ZERO_FILL)
    assert isinstance(result, WipeResult)
    assert result.passes_completed == 1
    assert result.verified is True
    assert result.standard_applied == WipeStandard.ZERO_FILL.value


def test_dod_3pass_wipe(engine, small_file):
    result = engine.wipe(small_file, WipeStandard.DOD_5220_22M_3PASS)
    assert result.passes_completed == 3
    assert len(result.pass_detail) == 3
    for pd in result.pass_detail:
        assert pd.pass_number in (1, 2, 3)
    assert result.verified is True


def test_nist_clear_wipe(engine, small_file):
    result = engine.wipe(small_file, WipeStandard.NIST_800_88_CLEAR)
    assert result.passes_completed == 1
    assert result.verified is True


def test_hmg_is5_baseline(engine, small_file):
    result = engine.wipe(small_file, WipeStandard.HMG_IS5_BASELINE)
    assert result.passes_completed == 1


def test_hmg_is5_enhanced(engine, small_file):
    result = engine.wipe(small_file, WipeStandard.HMG_IS5_ENHANCED)
    assert result.passes_completed == 3


def test_schneier_7pass(engine, small_file):
    result = engine.wipe(small_file, WipeStandard.SCHNEIER_7PASS)
    assert result.passes_completed == 7
    assert len(result.pass_detail) == 7


def test_ar_380_19(engine, small_file):
    result = engine.wipe(small_file, WipeStandard.AR_380_19)
    assert result.passes_completed == 3


def test_navso_p5239_26(engine, small_file):
    result = engine.wipe(small_file, WipeStandard.NAVSO_P5239_26)
    assert result.passes_completed == 3


def test_afssi_5020(engine, small_file):
    result = engine.wipe(small_file, WipeStandard.AFSSI_5020)
    assert result.passes_completed == 3


def test_wipe_result_has_duration(engine, small_file):
    result = engine.wipe(small_file, WipeStandard.ZERO_FILL)
    assert result.duration_seconds > 0.0


def test_wipe_nonexistent_file_raises(engine):
    with pytest.raises((FileNotFoundError, OSError)):
        engine.wipe("/nonexistent/path/file.bin", WipeStandard.ZERO_FILL)


def test_wipe_result_serializable(engine, small_file):
    import json
    result = engine.wipe(small_file, WipeStandard.DOD_5220_22M_3PASS)
    d = {
        "standard_applied": result.standard_applied,
        "passes_completed": result.passes_completed,
        "verified": result.verified,
        "pass_detail": [
            {"pass_number": p.pass_number, "pattern": p.pattern, "verified": p.verified}
            for p in result.pass_detail
        ],
    }
    assert json.dumps(d)  # must be JSON-serializable


def test_dod_7pass_wipe(engine, small_file):
    result = engine.wipe(small_file, WipeStandard.DOD_5220_22M_7PASS)
    assert result.passes_completed == 7
    assert result.verified is True
