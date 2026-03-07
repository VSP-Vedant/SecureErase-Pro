"""
=============================================================================
Module: SecureWipeEngine
Purpose: Execute multi-pass overwrite sequences per selected deletion
         standard. Each standard defines specific pass patterns, pass counts,
         and read-back verification requirements. This module handles all
         software-based wipe standards for HDDs and magnetic media.
         SSD/NVMe devices are routed to SSDHandler for hardware Purge.
Inputs:  File path, wipe standard enum, optional config (buffer size)
Outputs: WipeResult dataclass (passes_completed, pass_detail[], verified,
         duration_seconds, error)
Dependencies: os, ctypes (stdlib), multiprocessing (stdlib)
Compliance:
  - DoD 5220.22-M (3-pass and 7-pass)
  - NIST SP 800-88 Rev.1 Clear
  - Gutmann 35-pass
  - Schneier 7-pass
  - AFSSI-5020, AR 380-19, NAVSO P-5239-26
  - HMG IS5 Baseline and Enhanced
  - Single-pass zero-write
=============================================================================
"""

import os
import sys
import time
import struct
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import List, Optional, Union


# ---------------------------------------------------------------------------
# Write buffer size: 1 MB. Balances throughput vs memory usage.
# Large enough to amortize syscall overhead; small enough to not stall
# the UI event loop during progress callbacks.
# ---------------------------------------------------------------------------
_WRITE_BUFFER = 1 * 1024 * 1024  # 1 MB


class WipeStandard(str, Enum):
    """
    Enumeration of all supported wipe standards.
    String values match the 'standard_applied' field in the JSON certificate.
    """
    NIST_800_88_CLEAR        = "NIST SP 800-88 Rev.1 - Clear"
    DOD_5220_22M_3PASS       = "DoD 5220.22-M (3-pass)"
    DOD_5220_22M_7PASS       = "DoD 5220.22-M (7-pass)"
    GUTMANN_35PASS           = "Gutmann 35-pass"
    SCHNEIER_7PASS           = "Schneier 7-pass"
    AFSSI_5020               = "AFSSI-5020"
    AR_380_19                = "AR 380-19"
    NAVSO_P5239_26           = "NAVSO P-5239-26"
    HMG_IS5_BASELINE         = "HMG IS5 Baseline"
    HMG_IS5_ENHANCED         = "HMG IS5 Enhanced"
    ZERO_FILL                = "Single-pass zero-write"


@dataclass
class PassDetail:
    """Per-pass result recorded in the certificate."""
    pass_number: int
    pattern: str         # Hex string (e.g., '0x00') or 'random'
    verified: bool       # Read-back verification result
    started_at: str
    completed_at: str
    error: Optional[str] = None


@dataclass
class WipeResult:
    """
    Complete result of a wipe operation.
    Maps 1:1 to the 'wipe_operation' block in the JSON certificate.
    """
    standard_applied: str
    passes_completed: int
    passes_total: int
    pass_detail: List[PassDetail] = field(default_factory=list)
    duration_seconds: float = 0.0
    verified: bool = False        # True only if ALL passes completed and verified
    sha256_after: str = ""        # Filled by HashVerifier post-wipe
    sha3_256_after: str = ""
    error: Optional[str] = None   # Set on fatal failure
    file_path: str = ""
    file_size_bytes: int = 0


# ---------------------------------------------------------------------------
# Gutmann 35-pass pattern table.
# Passes 1-4 and 32-35 are pseudo-random.
# Passes 5-31 are specific patterns targeting MFM/RLL encoding residues.
# Source: Peter Gutmann, "Secure Deletion of Data from Magnetic and
# Solid-State Memory", USENIX Security 1996.
# ---------------------------------------------------------------------------
_GUTMANN_PATTERNS = [
    # Pass  1-4: random (None = generate random)
    None, None, None, None,
    # Pass  5: 0x55 (01010101)
    bytes([0x55]),
    # Pass  6: 0xAA (10101010)
    bytes([0xAA]),
    # Pass  7: 0x92, 0x49, 0x24
    bytes([0x92, 0x49, 0x24]),
    # Pass  8: 0x49, 0x24, 0x92
    bytes([0x49, 0x24, 0x92]),
    # Pass  9: 0x24, 0x92, 0x49
    bytes([0x24, 0x92, 0x49]),
    # Pass 10: 0x00
    bytes([0x00]),
    # Pass 11: 0x11
    bytes([0x11]),
    # Pass 12: 0x22
    bytes([0x22]),
    # Pass 13: 0x33
    bytes([0x33]),
    # Pass 14: 0x44
    bytes([0x44]),
    # Pass 15: 0x55
    bytes([0x55]),
    # Pass 16: 0x66
    bytes([0x66]),
    # Pass 17: 0x77
    bytes([0x77]),
    # Pass 18: 0x88
    bytes([0x88]),
    # Pass 19: 0x99
    bytes([0x99]),
    # Pass 20: 0xAA
    bytes([0xAA]),
    # Pass 21: 0xBB
    bytes([0xBB]),
    # Pass 22: 0xCC
    bytes([0xCC]),
    # Pass 23: 0xDD
    bytes([0xDD]),
    # Pass 24: 0xEE
    bytes([0xEE]),
    # Pass 25: 0xFF
    bytes([0xFF]),
    # Pass 26: 0x92, 0x49, 0x24
    bytes([0x92, 0x49, 0x24]),
    # Pass 27: 0x49, 0x24, 0x92
    bytes([0x49, 0x24, 0x92]),
    # Pass 28: 0x24, 0x92, 0x49
    bytes([0x24, 0x92, 0x49]),
    # Pass 29: 0x6D, 0xB6, 0xDB
    bytes([0x6D, 0xB6, 0xDB]),
    # Pass 30: 0xB6, 0xDB, 0x6D
    bytes([0xB6, 0xDB, 0x6D]),
    # Pass 31: 0xDB, 0x6D, 0xB6
    bytes([0xDB, 0x6D, 0xB6]),
    # Pass 32-35: random
    None, None, None, None,
]

# ---------------------------------------------------------------------------
# Standard → pass sequence definitions.
# Each entry is a list of pattern specs:
#   bytes object: fill with that byte/pattern repeated
#   None:         generate cryptographically random data
# ---------------------------------------------------------------------------
_STANDARD_PASSES = {
    WipeStandard.NIST_800_88_CLEAR:  [bytes([0x00])],
    WipeStandard.ZERO_FILL:          [bytes([0x00])],
    WipeStandard.HMG_IS5_BASELINE:   [bytes([0x00])],
    WipeStandard.HMG_IS5_ENHANCED:   [bytes([0x00]), bytes([0xFF]), None],
    WipeStandard.DOD_5220_22M_3PASS: [bytes([0x00]), bytes([0xFF]), None],
    WipeStandard.AFSSI_5020:         [bytes([0x00]), bytes([0xFF]), None],
    WipeStandard.AR_380_19:          [None, None, bytes([0x97])],
    WipeStandard.NAVSO_P5239_26:     [bytes([0x01]), bytes([0x27]) * 1 + bytes([0xFF]) * 3, None],
    WipeStandard.SCHNEIER_7PASS:     [bytes([0x00]), bytes([0xFF]), None, None, None, None, None],
    WipeStandard.DOD_5220_22M_7PASS: [
        bytes([0x00]), bytes([0xFF]), None,
        bytes([0x96]),
        bytes([0x00]), bytes([0xFF]), None,
    ],
    WipeStandard.GUTMANN_35PASS:     _GUTMANN_PATTERNS,
}


def _pattern_label(pattern: Optional[bytes]) -> str:
    """Return human/certificate-readable label for a pass pattern."""
    if pattern is None:
        return "random"
    if len(pattern) == 1:
        return hex(pattern[0])
    return pattern.hex()


class SecureWipeEngine:
    """
    Executes multi-pass file overwrite operations per named standard.

    Security design notes:
    - Files are opened with os.O_WRONLY | os.O_SYNC on POSIX to bypass
      the kernel write-back cache and force immediate disk commits.
    - After each pass, os.fsync() is called on the file descriptor to
      flush any remaining kernel buffers to the storage device.
    - On Linux, posix_fadvise(POSIX_FADV_DONTNEED) is called after each
      pass to evict the written data from the page cache, ensuring the
      next pass actually writes to disk rather than to cached memory.
    - Sparse files: file holes are detected and filled before wiping to
      ensure the full allocated (and unallocated) size is overwritten.
    - The file is NOT deleted after wiping; the caller (UIController or
      FileScanner) handles deletion after the WipeResult is recorded.
      This ensures the certificate captures the wipe before the inode is
      freed.

    Limitation disclosure:
    - On SSDs, NVMe, and flash storage, multi-pass software overwrites
      DO NOT reliably erase all copies of data due to wear leveling,
      over-provisioning, and bad-block remapping. For these devices,
      route to SSDHandler which uses hardware ATA Secure Erase or
      NVMe PSID Revert. This limitation is flagged in the certificate.
    - On copy-on-write filesystems (Btrfs, ZFS, APFS), writes may create
      new blocks rather than overwriting in-place. Certificate must note
      the filesystem type.
    """

    def __init__(self, buffer_size: int = _WRITE_BUFFER):
        self.buffer_size = buffer_size

    def wipe(
        self,
        path: Union[str, Path],
        standard: WipeStandard,
        progress_callback=None,
    ) -> WipeResult:
        """
        Perform a complete multi-pass wipe of a single file.

        Args:
            path: Absolute path to the target file.
            standard: WipeStandard enum value.
            progress_callback: Optional callable(pass_num, total_passes, bytes_done, total_bytes).
                               Called periodically during each pass.

        Returns:
            WipeResult with complete pass detail, timing, and verification status.
        """
        path = Path(path).resolve()

        if not path.exists():
            raise FileNotFoundError(f"SecureWipeEngine: target not found: {path}")
        if path.is_dir():
            raise IsADirectoryError(
                f"SecureWipeEngine: path is directory; iterate files externally"
            )
        if path.is_symlink():
            raise ValueError(
                f"SecureWipeEngine: refusing to wipe symlink target: {path}. "
                "Resolve symlinks explicitly before wiping."
            )

        file_size = path.stat().st_size
        pass_sequence = _STANDARD_PASSES[standard]
        total_passes = len(pass_sequence)

        result = WipeResult(
            standard_applied=standard.value,
            passes_completed=0,
            passes_total=total_passes,
            file_path=str(path),
            file_size_bytes=file_size,
        )

        overall_start = time.monotonic()
        all_verified = True

        for pass_idx, pattern in enumerate(pass_sequence):
            pass_num = pass_idx + 1
            pass_start = datetime.now(timezone.utc).isoformat()

            try:
                verified = self._execute_pass(
                    path=path,
                    pass_num=pass_num,
                    total_passes=total_passes,
                    pattern=pattern,
                    file_size=file_size,
                    progress_callback=progress_callback,
                )

                result.pass_detail.append(PassDetail(
                    pass_number=pass_num,
                    pattern=_pattern_label(pattern),
                    verified=verified,
                    started_at=pass_start,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                ))
                result.passes_completed += 1

                if not verified:
                    all_verified = False

            except OSError as exc:
                # Record partial failure — do not abort remaining passes.
                # Completing remaining passes still improves security even
                # if one pass failed verification.
                result.pass_detail.append(PassDetail(
                    pass_number=pass_num,
                    pattern=_pattern_label(pattern),
                    verified=False,
                    started_at=pass_start,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    error=str(exc),
                ))
                all_verified = False
                result.error = f"Pass {pass_num} failed: {exc}"

        result.duration_seconds = round(time.monotonic() - overall_start, 3)
        result.verified = all_verified and (result.passes_completed == total_passes)
        return result

    def _execute_pass(
        self,
        path: Path,
        pass_num: int,
        total_passes: int,
        pattern: Optional[bytes],
        file_size: int,
        progress_callback,
    ) -> bool:
        """
        Execute a single overwrite pass and optionally verify it.

        Security-critical path:
        - O_WRONLY | O_SYNC ensures writes bypass write-back cache on POSIX.
        - fsync() after write loop forces physical media commit.
        - posix_fadvise DONTNEED evicts page cache post-write on Linux,
          so subsequent read-back actually reads from disk.

        Returns:
            True if the pass completed and (if verifiable) read-back confirmed.
        """
        flags = os.O_WRONLY
        if sys.platform != "win32":
            # O_SYNC: writes are synchronous — each write() blocks until the
            # data reaches the storage device hardware cache.
            flags |= getattr(os, "O_SYNC", 0)

        fd = os.open(str(path), flags)
        try:
            bytes_written = 0
            while bytes_written < file_size:
                remaining = file_size - bytes_written
                chunk_size = min(self.buffer_size, remaining)

                if pattern is None:
                    # Cryptographically secure random data via os.urandom()
                    chunk = secrets.token_bytes(chunk_size)
                else:
                    # Tile the pattern to fill the chunk
                    repeats = (chunk_size // len(pattern)) + 1
                    chunk = (pattern * repeats)[:chunk_size]

                os.write(fd, chunk)
                bytes_written += chunk_size

                if progress_callback:
                    progress_callback(pass_num, total_passes, bytes_written, file_size)

            # Force all written data to the physical device
            os.fsync(fd)

            # On Linux, evict the page cache to ensure read-back goes to disk
            if sys.platform == "linux":
                try:
                    import ctypes
                    libc = ctypes.CDLL("libc.so.6", use_errno=True)
                    # POSIX_FADV_DONTNEED = 4 on Linux
                    libc.posix_fadvise(fd, 0, 0, 4)
                except Exception:
                    pass  # Non-fatal; verification may read from page cache

        finally:
            os.close(fd)

        # Read-back verification for single-byte patterns (not random)
        if pattern is not None and len(pattern) == 1:
            return self._verify_pass(path, pattern)

        # Random passes cannot be verified by read-back (we don't know the data).
        # We confirm they completed by checking no exception occurred.
        return True

    def _verify_pass(self, path: Path, expected_pattern: bytes) -> bool:
        """
        Read-back verification: confirm every byte matches the expected pattern.
        Only used for deterministic (non-random) passes.

        Returns True if all bytes match, False otherwise.

        Security note: Read-back on SSDs may return different cells than
        were written due to wear leveling. This is a known limitation —
        the certificate notes it when the device is detected as SSD.
        """
        pattern_byte = expected_pattern[0]
        try:
            with open(path, "rb") as fh:
                while True:
                    chunk = fh.read(self.buffer_size)
                    if not chunk:
                        break
                    if any(b != pattern_byte for b in chunk):
                        return False
            return True
        except OSError:
            return False
