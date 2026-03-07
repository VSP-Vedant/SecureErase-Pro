"""
=============================================================================
Module: FileScanner
Purpose: Recursively discover files and folders, extract metadata, detect
         device type (HDD/SSD/NVMe), detect filesystem type, and resolve
         symlinks. Produces FileEntry objects consumed by SecureWipeEngine
         and CertificateBuilder.
Inputs:  Target path(s), exclusion patterns
Outputs: List[FileEntry], scan summary stats
Dependencies: os, stat, pathlib, subprocess (stdlib)
Compliance:
  - Supports multi-file batch wipe operations required by enterprise
    IT asset disposal workflows (NIST SP 800-88, PCI-DSS Req. 9.4.6)
=============================================================================
"""

import os
import platform
import re
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple


@dataclass
class FileEntry:
    """
    Metadata about a target file or directory.
    Consumed by SecureWipeEngine, HashVerifier, and CertificateBuilder.
    """
    path: str
    type: str              # "file" | "folder"
    size_bytes: int
    file_count: int        # 1 for files; total files in folder
    device_type: str       # "HDD" | "SSD" | "NVMe" | "unknown"
    filesystem: str        # e.g. "ext4", "NTFS", "APFS"
    is_ssd: bool = False
    is_symlink: bool = False
    inode: Optional[int] = None
    permissions: str = ""  # Octal string e.g. "0644"
    children: List[str] = field(default_factory=list)  # Paths for folder targets


@dataclass
class ScanResult:
    """Summary of a scan operation."""
    total_files: int
    total_size_bytes: int
    entries: List[FileEntry]
    warnings: List[str] = field(default_factory=list)


class FileScanner:
    """
    Enumerates files for wipe operations.

    Security design:
    - Symlinks are detected and NOT followed by default. Wiping a symlink
      target could erase unintended files (TOCTOU race condition). The caller
      must explicitly pass follow_symlinks=True.
    - Locked/open files are flagged as warnings, not errors — the wipe engine
      will attempt the wipe and report failure if the file is still locked.
    - Network drives are detected via mount point inspection and flagged:
      multi-pass wipes over network drives may not guarantee physical erasure
      on the server side. The certificate records the filesystem/mount type.
    - COW (Copy-on-Write) filesystems (Btrfs, ZFS, APFS) are detected and
      flagged in the certificate — software overwrites may not be in-place.
    """

    COW_FILESYSTEMS = {"btrfs", "zfs", "apfs", "bcachefs", "nilfs2"}
    NETWORK_FILESYSTEMS = {"nfs", "cifs", "smb", "smbfs", "nfs4", "afs", "sshfs"}

    def scan(
        self,
        path: str,
        exclusions: Optional[List[str]] = None,
        follow_symlinks: bool = False,
    ) -> ScanResult:
        """
        Scan a file or directory path and return FileEntry objects.

        Args:
            path: Absolute path to file or directory.
            exclusions: List of glob patterns to exclude (e.g. ['*.tmp', '.git']).
            follow_symlinks: If True, follow and scan symlink targets.

        Returns:
            ScanResult with entries and any warnings.
        """
        path_obj = Path(path).resolve()
        exclusions = exclusions or []
        warnings = []

        if not path_obj.exists():
            raise FileNotFoundError(f"FileScanner: path not found: {path}")

        entries = []

        if path_obj.is_file() or (path_obj.is_symlink() and follow_symlinks):
            entry, warn = self._scan_file(path_obj, follow_symlinks)
            entries.append(entry)
            warnings.extend(warn)

        elif path_obj.is_dir():
            entry, warn = self._scan_directory(path_obj, exclusions, follow_symlinks)
            entries.append(entry)
            warnings.extend(warn)

        elif path_obj.is_symlink() and not follow_symlinks:
            warnings.append(
                f"Symlink detected at {path_obj} — skipped. "
                "Pass follow_symlinks=True to include symlink targets."
            )

        else:
            warnings.append(f"Skipped special file (device/socket/pipe): {path_obj}")

        total_files = sum(e.file_count for e in entries)
        total_size = sum(e.size_bytes for e in entries)

        return ScanResult(
            total_files=total_files,
            total_size_bytes=total_size,
            entries=entries,
            warnings=warnings,
        )

    def _scan_file(self, path: Path, follow_symlinks: bool) -> Tuple[FileEntry, List[str]]:
        """Build a FileEntry for a single file."""
        warnings = []
        stat_result = path.stat()
        inode = stat_result.st_ino
        size = stat_result.st_size
        mode = stat.filemode(stat_result.st_mode)
        permissions = oct(stat_result.st_mode & 0o777)
        is_symlink = path.is_symlink()

        if is_symlink and not follow_symlinks:
            warnings.append(f"Symlink: {path} — will wipe the link, not the target")

        # Detect locked/open files (Linux only via /proc/locks)
        if self._is_file_locked(path):
            warnings.append(f"File may be locked/in-use by another process: {path}")

        device_type, filesystem = self._get_device_info(path)
        is_ssd = device_type in ("SSD", "NVMe")

        if filesystem.lower() in self.COW_FILESYSTEMS:
            warnings.append(
                f"COW filesystem detected ({filesystem}) for {path}. "
                "Software overwrites may NOT be in-place. "
                "NIST SP 800-88 Purge via hardware command is required."
            )

        if filesystem.lower() in self.NETWORK_FILESYSTEMS:
            warnings.append(
                f"Network filesystem detected ({filesystem}) for {path}. "
                "Wipe overwrites data on the client side only; server-side "
                "physical erasure cannot be guaranteed."
            )

        return FileEntry(
            path=str(path),
            type="file",
            size_bytes=size,
            file_count=1,
            device_type=device_type,
            filesystem=filesystem,
            is_ssd=is_ssd,
            is_symlink=is_symlink,
            inode=inode,
            permissions=permissions,
        ), warnings

    def _scan_directory(
        self,
        path: Path,
        exclusions: List[str],
        follow_symlinks: bool,
    ) -> Tuple[FileEntry, List[str]]:
        """Build a FileEntry for a directory (recursive)."""
        warnings = []
        total_size = 0
        file_count = 0
        children = []

        device_type, filesystem = self._get_device_info(path)
        is_ssd = device_type in ("SSD", "NVMe")

        if filesystem.lower() in self.COW_FILESYSTEMS:
            warnings.append(
                f"COW filesystem ({filesystem}) at {path}: software wipe not guaranteed in-place."
            )

        for item in sorted(path.rglob("*")):
            # Apply exclusion patterns
            if any(item.match(pat) for pat in exclusions):
                continue

            if item.is_symlink() and not follow_symlinks:
                warnings.append(f"Symlink skipped in directory scan: {item}")
                continue

            if item.is_file():
                try:
                    size = item.stat().st_size
                    total_size += size
                    file_count += 1
                    children.append(str(item))
                except OSError as e:
                    warnings.append(f"Could not stat {item}: {e}")

        return FileEntry(
            path=str(path),
            type="folder",
            size_bytes=total_size,
            file_count=file_count,
            device_type=device_type,
            filesystem=filesystem,
            is_ssd=is_ssd,
            children=children,
        ), warnings

    def _get_device_info(self, path: Path) -> Tuple[str, str]:
        """
        Detect device type (HDD/SSD/NVMe) and filesystem type for a path.
        Returns (device_type, filesystem).
        """
        try:
            if platform.system() == "Linux":
                return self._linux_device_info(path)
            elif platform.system() == "Darwin":
                return self._macos_device_info(path)
            elif platform.system() == "Windows":
                return self._windows_device_info(path)
        except Exception:
            pass
        return "unknown", "unknown"

    def _linux_device_info(self, path: Path) -> Tuple[str, str]:
        """Linux: use df for filesystem, /sys/block for rotation flag."""
        # Get filesystem type
        df = subprocess.run(
            ["df", "--output=source,fstype", str(path)],
            capture_output=True, text=True, check=False
        )
        lines = df.stdout.strip().split("\n")
        device, fstype = "unknown", "unknown"
        if len(lines) > 1:
            parts = lines[-1].split()
            if len(parts) >= 2:
                device, fstype = parts[0], parts[1]

        # Get rotational flag
        base_dev = re.sub(r'\d+$', '', Path(device).name)  # strip partition num
        rotational_path = f"/sys/block/{base_dev}/queue/rotational"
        is_nvme = "nvme" in device
        rotational = True

        if os.path.exists(rotational_path):
            with open(rotational_path) as f:
                rotational = f.read().strip() == "1"

        if is_nvme:
            return "NVMe", fstype
        elif not rotational:
            return "SSD", fstype
        else:
            return "HDD", fstype

    def _macos_device_info(self, path: Path) -> Tuple[str, str]:
        """macOS: use diskutil info."""
        result = subprocess.run(
            ["diskutil", "info", str(path)],
            capture_output=True, text=True, check=False
        )
        output = result.stdout.lower()
        fstype = "apfs" if "apfs" in output else ("hfs" if "hfs" in output else "unknown")
        # SSD detection via Solid State field
        is_ssd = "solid state: yes" in output
        device_type = "SSD" if is_ssd else "HDD"
        return device_type, fstype

    def _windows_device_info(self, path: Path) -> Tuple[str, str]:
        """Windows: use PowerShell to detect drive type and filesystem."""
        try:
            drive = str(path.anchor).rstrip("\\")
            result = subprocess.run(
                ["powershell", "-Command",
                 f"Get-PhysicalDisk | Where-Object {{$_.DeviceID -eq "
                 f"(Get-Partition -DriveLetter '{drive[0]}').DiskNumber}} | "
                 f"Select-Object -ExpandProperty MediaType"],
                capture_output=True, text=True, check=False
            )
            media = result.stdout.strip().lower()
            device_type = "SSD" if "ssd" in media else "HDD"

            fstype_result = subprocess.run(
                ["powershell", "-Command",
                 f"(Get-Volume -DriveLetter '{drive[0]}').FileSystem"],
                capture_output=True, text=True, check=False
            )
            fstype = fstype_result.stdout.strip() or "unknown"
            return device_type, fstype
        except Exception:
            return "unknown", "unknown"

    def _is_file_locked(self, path: Path) -> bool:
        """Check if a file is currently open by another process (Linux only)."""
        if platform.system() != "Linux":
            return False
        try:
            result = subprocess.run(
                ["lsof", str(path)],
                capture_output=True, check=False
            )
            return result.returncode == 0 and len(result.stdout) > 0
        except Exception:
            return False
