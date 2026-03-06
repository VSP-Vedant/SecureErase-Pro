"""
FileScanner
===========
Purpose:    Recursively discover files and folders, extract metadata,
            and resolve symlinks. Produces a list of FileEntry objects
            consumed by SecureWipeEngine and CertificateBuilder.

Inputs:     - One or more target paths
            - Exclusion patterns (glob or regex)
            - Whether to follow symlinks (default: False — security)

Outputs:    - List[FileEntry] with full metadata
            - ScanResult summary

Dependencies:
            - os, pathlib, stat, datetime (stdlib)

Security notes:
            - Symlinks are NOT followed by default to prevent scope creep
              (accidentally wiping files outside the intended directory).
            - TOCTOU warning: Metadata is captured at scan time. The wipe
              engine re-checks file existence before opening. Any delta
              (file deleted/moved between scan and wipe) is recorded in
              WipeResult.error.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Union


@dataclass
class FileEntry:
    path: str
    entry_type: str      # "file" or "folder"
    size_bytes: int
    file_count: int      # 1 for files, recursive count for folders
    is_symlink: bool
    is_hidden: bool
    mtime: str           # ISO 8601 UTC
    permissions: str     # octal string e.g. "0o644"
    inode: int

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "type": self.entry_type,
            "size_bytes": self.size_bytes,
            "file_count": self.file_count,
            "is_symlink": self.is_symlink,
            "is_hidden": self.is_hidden,
            "mtime": self.mtime,
            "permissions": self.permissions,
            "inode": self.inode,
        }


@dataclass
class ScanResult:
    entries: List[FileEntry]
    total_size_bytes: int
    total_file_count: int
    excluded_count: int
    scan_duration_seconds: float
    errors: List[str] = field(default_factory=list)


class FileScanner:

    def __init__(self, follow_symlinks: bool = False):
        self._follow_symlinks = follow_symlinks

    def scan(
        self,
        targets: Union[str, Path, List[Union[str, Path]]],
        exclude_patterns: Optional[List[str]] = None,
    ) -> ScanResult:
        """
        Scan one or more paths and return metadata for all discovered files.
        """
        import time
        start = time.monotonic()

        if isinstance(targets, (str, Path)):
            targets = [targets]

        entries: List[FileEntry] = []
        total_size = 0
        total_files = 0
        excluded = 0
        errors: List[str] = []

        for target in targets:
            path = Path(target).resolve()
            if path.is_file():
                entry = self._file_entry(path)
                if entry:
                    if self._is_excluded(path, exclude_patterns):
                        excluded += 1
                    else:
                        entries.append(entry)
                        total_size += entry.size_bytes
                        total_files += 1
            elif path.is_dir():
                entry, dir_errors = self._dir_entry(path, exclude_patterns)
                excluded += entry.file_count  # re-counted below
                entries.append(entry)
                total_size += entry.size_bytes
                total_files += entry.file_count
                errors.extend(dir_errors)
            else:
                errors.append(f"Path does not exist or is unreadable: {path}")

        return ScanResult(
            entries=entries,
            total_size_bytes=total_size,
            total_file_count=total_files,
            excluded_count=excluded,
            scan_duration_seconds=time.monotonic() - start,
            errors=errors,
        )

    def _file_entry(self, path: Path) -> Optional[FileEntry]:
        try:
            s = path.stat()
            return FileEntry(
                path=str(path),
                entry_type="file",
                size_bytes=s.st_size,
                file_count=1,
                is_symlink=path.is_symlink(),
                is_hidden=path.name.startswith("."),
                mtime=datetime.fromtimestamp(s.st_mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                permissions=oct(stat.S_IMODE(s.st_mode)),
                inode=s.st_ino,
            )
        except OSError:
            return None

    def _dir_entry(
        self,
        path: Path,
        exclude_patterns: Optional[List[str]],
    ) -> tuple[FileEntry, List[str]]:
        total_size = 0
        file_count = 0
        errors: List[str] = []
        try:
            s = path.stat()
            for fp in path.rglob("*"):
                if fp.is_file() and not (fp.is_symlink() and not self._follow_symlinks):
                    if not self._is_excluded(fp, exclude_patterns):
                        try:
                            total_size += fp.stat().st_size
                            file_count += 1
                        except OSError as e:
                            errors.append(str(e))
            return FileEntry(
                path=str(path),
                entry_type="folder",
                size_bytes=total_size,
                file_count=file_count,
                is_symlink=path.is_symlink(),
                is_hidden=path.name.startswith("."),
                mtime=datetime.fromtimestamp(s.st_mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                permissions=oct(stat.S_IMODE(s.st_mode)),
                inode=s.st_ino,
            ), errors
        except OSError as e:
            errors.append(str(e))
            return FileEntry(
                path=str(path), entry_type="folder",
                size_bytes=0, file_count=0,
                is_symlink=False, is_hidden=False,
                mtime="", permissions="", inode=0,
            ), errors

    @staticmethod
    def _is_excluded(path: Path, patterns: Optional[List[str]]) -> bool:
        if not patterns:
            return False
        for pat in patterns:
            if path.match(pat):
                return True
        return False
