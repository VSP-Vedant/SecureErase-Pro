"""
Tests: HashVerifier
"""
import os
import tempfile
import pytest
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from desktop.modules.hash_verifier import hash_file, hash_bytes, HashResult


def test_hash_bytes_sha256():
    result = hash_bytes(b"hello world")
    # SHA-256 of b"hello world"
    assert result.sha256 == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    assert len(result.sha256) == 64
    assert len(result.sha3_256) == 64


def test_hash_bytes_empty():
    result = hash_bytes(b"")
    assert len(result.sha256) == 64


def test_hash_file_creates_correct_hash(tmp_path):
    f = tmp_path / "test.bin"
    content = b"SecureErase Pro test content 12345"
    f.write_bytes(content)
    result = hash_file(str(f))
    expected = hash_bytes(content)
    assert result.sha256 == expected.sha256
    assert result.sha3_256 == expected.sha3_256


def test_hash_file_not_found():
    with pytest.raises(FileNotFoundError):
        hash_file("/nonexistent/path/file.txt")


def test_two_different_files_have_different_hashes(tmp_path):
    f1 = tmp_path / "a.txt"; f1.write_bytes(b"data A")
    f2 = tmp_path / "b.txt"; f2.write_bytes(b"data B")
    r1 = hash_file(str(f1))
    r2 = hash_file(str(f2))
    assert r1.sha256 != r2.sha256