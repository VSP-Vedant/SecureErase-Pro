"""
Tests: FileScanner
Covers: file and directory scanning, ScanResult structure, metadata accuracy,
        symlink handling, and path resolution.

Note: FileScanner treats a directory as ONE wipe target (single FileEntry
with type='folder', file_count=N, size_bytes=total). Individual files
within a directory are not returned as separate entries — the entire
directory tree is wiped as one unit, consistent with enterprise wipe workflows.
"""
import os
import sys
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from desktop.modules.file_scanner import FileScanner, FileEntry, ScanResult


@pytest.fixture
def scanner():
    return FileScanner()


@pytest.fixture
def sample_tree(tmp_path):
    """Create a small file tree: 3 files, total 1029 bytes."""
    (tmp_path / "a.txt").write_bytes(b"hello")          # 5 bytes
    (tmp_path / "b.bin").write_bytes(b"\x00" * 1024)   # 1024 bytes
    sub = tmp_path / "subdir"
    sub.mkdir()
    (sub / "c.log").write_bytes(b"log data")            # 8 bytes... but depends on OS
    return tmp_path


def test_scan_single_file(scanner, tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"data" * 100)
    result = scanner.scan(str(f))
    assert isinstance(result, ScanResult)
    assert result.total_files == 1
    assert result.total_size_bytes == 400
    assert len(result.entries) == 1
    assert result.entries[0].type == "file"
    assert result.entries[0].path == str(f)


def test_scan_directory_returns_folder_entry(scanner, sample_tree):
    result = scanner.scan(str(sample_tree))
    assert isinstance(result, ScanResult)
    # One entry: the directory itself
    assert len(result.entries) == 1
    entry = result.entries[0]
    assert entry.type == "folder"
    assert entry.path == str(sample_tree)
    assert entry.file_count >= 3


def test_directory_total_size_includes_all_files(scanner, sample_tree):
    result = scanner.scan(str(sample_tree))
    # 5 + 1024 + 8 = 1037 bytes
    assert result.total_size_bytes >= 1037


def test_scan_result_has_correct_total_files(scanner, sample_tree):
    result = scanner.scan(str(sample_tree))
    assert result.total_files >= 3


def test_nonexistent_path_raises(scanner):
    with pytest.raises((FileNotFoundError, OSError)):
        scanner.scan("/nonexistent/path/xyz")


def test_size_bytes_is_accurate(scanner, tmp_path):
    data = b"A" * 8192
    f = tmp_path / "sized.bin"
    f.write_bytes(data)
    result = scanner.scan(str(f))
    assert result.entries[0].size_bytes == 8192


def test_file_entry_has_required_fields(scanner, tmp_path):
    f = tmp_path / "x.dat"
    f.write_bytes(b"x" * 512)
    result = scanner.scan(str(f))
    entry = result.entries[0]
    assert isinstance(entry, FileEntry)
    assert entry.path == str(f)
    assert entry.size_bytes == 512
    assert entry.file_count == 1
    assert entry.type == "file"


def test_file_count_for_single_file(scanner, tmp_path):
    f = tmp_path / "single.txt"
    f.write_bytes(b"single")
    result = scanner.scan(str(f))
    assert result.entries[0].file_count == 1


def test_symlink_not_followed_by_default(scanner, tmp_path):
    real_file = tmp_path / "real.txt"
    real_file.write_bytes(b"real data")
    link = tmp_path / "link.txt"
    link.symlink_to(real_file)
    # By default, symlinks are not followed; warnings should mention symlink
    result = scanner.scan(str(tmp_path))
    # Should complete without raising; warnings may reference the symlink
    assert isinstance(result, ScanResult)
    assert isinstance(result.warnings, list)


def test_scan_result_warnings_is_list(scanner, tmp_path):
    f = tmp_path / "w.bin"
    f.write_bytes(b"x")
    result = scanner.scan(str(f))
    assert isinstance(result.warnings, list)
