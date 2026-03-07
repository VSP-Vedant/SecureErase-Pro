"""
=============================================================================
Module: AuditLogger
Purpose: Append-only, tamper-evident local audit log using HMAC-SHA256
         chain linking. Each log entry includes the HMAC of the previous
         entry, making insertion, deletion, or modification of any entry
         detectable by chain verification.
Inputs:  Event dict (type, data, timestamp)
Outputs: Appended JSONL log file; chain verification result
Dependencies: hmac, hashlib, json (stdlib)
Compliance:
  - ISO/IEC 27001:2022 A.8.15 (Logging)
  - NIST SP 800-53 Rev.5 AU-9 (Protection of audit information)
  - PCI-DSS v4.0 Requirement 10 (Log management)
  - SOC 2 CC7.2 (Detection of anomalies and events)
=============================================================================
"""

import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional, List, Union


class AuditEventType(str, Enum):
    WIPE_STARTED         = "wipe_started"
    WIPE_COMPLETED       = "wipe_completed"
    WIPE_FAILED          = "wipe_failed"
    CERTIFICATE_ISSUED   = "certificate_issued"
    CERTIFICATE_SIGNED   = "certificate_signed"
    REGISTRY_UPLOAD      = "registry_upload"
    REGISTRY_UPLOAD_FAIL = "registry_upload_fail"
    APP_STARTED          = "app_started"
    APP_STOPPED          = "app_stopped"
    KEY_LOADED           = "key_loaded"
    CHAIN_VERIFIED       = "chain_verified"
    CHAIN_BROKEN         = "chain_broken"
    EXPORT_COMPLETED     = "export_completed"
    SYSTEM_EVENT         = "system_event"   # Catch-all for unrecognized event types


@dataclass
class AuditEntry:
    """Single audit log entry."""
    sequence: int
    event_type: str
    timestamp: str
    data: dict
    prev_hash: str    # HMAC-SHA256 of previous entry's canonical JSON
    entry_hash: str   # HMAC-SHA256 of this entry (excluding entry_hash field)

    def to_dict(self) -> dict:
        return asdict(self)


class AuditLogger:
    """
    Tamper-evident append-only audit log.

    Security design:
    - Each entry's prev_hash is the HMAC-SHA256 of the previous entry's
      canonical JSON (sorted keys, no whitespace). This creates a hash chain:
      modifying any past entry breaks the chain from that point forward.
    - The HMAC key is loaded from KeyManager (or a local key file). Using
      HMAC rather than a plain hash prevents an attacker who has the log file
      from forging valid entries — they would need the HMAC key too.
    - The log file is JSONL (one JSON object per line) for easy parsing and
      streaming append without loading the entire file.
    - Log rotation: when the log exceeds max_size_mb, it is rotated with a
      timestamp suffix. Old rotated logs are not deleted by this module —
      deletion policy is managed by enterprise IT.
    - Thread safety: A threading.Lock ensures concurrent wipe operations
      (running in separate processes/threads) don't interleave log writes.
    - The first entry uses prev_hash = "GENESIS" to mark the chain start.

    Limitation: The HMAC key itself must be protected. If an attacker obtains
    the HMAC key, they can forge entries. For maximum security, the HMAC key
    should be stored in the OS keychain or on a PKCS#11 HSM.
    """

    GENESIS = "GENESIS"

    def __init__(
        self,
        log_dir: Union[str, Path] = None,
        log_filename: str = "secureerase_audit.jsonl",
        hmac_key: Optional[bytes] = None,
        max_size_mb: int = 100,
    ):
        """
        Args:
            log_dir: Directory for log files. Defaults to OS-appropriate path.
            log_filename: Base filename for the log.
            hmac_key: 32+ byte key for HMAC chain. If None, a key is generated
                      and stored locally (less secure; use KeyManager in prod).
            max_size_mb: Rotate log when it exceeds this size.
        """
        if log_dir is None:
            log_dir = self._default_log_dir()

        p = Path(log_dir)
        # If the path looks like a file (has a file extension), treat it as
        # the full log file path rather than a directory.
        if p.suffix in (".log", ".jsonl", ".txt") or (p.parent.exists() and not p.is_dir()):
            self.log_dir = p.parent
            self.log_path = p
            self.log_dir.mkdir(parents=True, exist_ok=True)
        else:
            self.log_dir = p
            self.log_dir.mkdir(parents=True, exist_ok=True)
            self.log_path = self.log_dir / log_filename
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self._lock = threading.Lock()

        # Load or generate HMAC key
        if hmac_key:
            self.hmac_key = hmac_key
        else:
            self.hmac_key = self._load_or_generate_key()

        # Load the last entry's hash for chain continuity
        self._last_hash = self._load_last_hash()
        self._sequence = self._load_last_sequence()

    def log_event(
        self,
        event_type,
        data: dict,
    ) -> "AuditEntry":
        """
        Append a new event to the audit log.

        Args:
            event_type: Type of audit event — AuditEventType enum or plain string.
            data: Event-specific data dict. Must be JSON-serializable.
                  Sensitive fields (passwords, keys) must NOT be included.

        Returns:
            The AuditEntry that was written.
        """
        # Coerce string → AuditEventType gracefully
        if not isinstance(event_type, AuditEventType):
            try:
                event_type = AuditEventType(event_type)
            except ValueError:
                event_type = AuditEventType.SYSTEM_EVENT
        with self._lock:
            # Rotate log if size limit exceeded
            if self.log_path.exists() and self.log_path.stat().st_size > self.max_size_bytes:
                self._rotate_log()

            self._sequence += 1
            timestamp = datetime.now(timezone.utc).isoformat()

            # Build entry without entry_hash first
            entry_data = {
                "sequence": self._sequence,
                "event_type": event_type.value if isinstance(event_type, AuditEventType) else event_type,
                "timestamp": timestamp,
                "data": data,
                "prev_hash": self._last_hash,
                "entry_hash": "",  # placeholder
            }

            # Compute HMAC of entry (without entry_hash)
            entry_json = json.dumps(entry_data, sort_keys=True, separators=(",", ":"))
            entry_hmac = hmac.new(
                self.hmac_key,
                entry_json.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()

            entry_data["entry_hash"] = entry_hmac

            # Append to JSONL file
            line = json.dumps(entry_data, sort_keys=True, separators=(",", ":"))
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                # fsync to ensure the log entry is on disk before returning
                f.flush()
                os.fsync(f.fileno())

            self._last_hash = entry_hmac
            return AuditEntry(**entry_data)

    def verify_chain(self) -> bool:
        """
        Verify the integrity of the entire audit log chain.
        Returns True if the chain is intact, False if any entry is tampered.
        For full detail (entry counts, error location), use verify_chain_detail().
        """
        return self.verify_chain_detail()["valid"]

    def verify_chain_detail(self) -> dict:
        """
        Verify the integrity of the entire audit log chain.

        Process:
        1. Read all entries in order.
        2. For each entry, recompute its HMAC (excluding entry_hash field).
        3. Verify computed HMAC matches stored entry_hash.
        4. Verify prev_hash matches the entry_hash of the preceding entry.

        Returns:
            Dict with 'valid' (bool), 'total_entries', 'first_broken_at' (seq or None),
            'error' (str or None).
        """
        if not self.log_path.exists():
            return {"valid": True, "total_entries": 0, "first_broken_at": None, "error": None}

        entries = []
        with open(self.log_path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError as e:
                    return {
                        "valid": False,
                        "total_entries": lineno - 1,
                        "first_broken_at": lineno,
                        "error": f"JSON parse error at line {lineno}: {e}",
                    }

        prev_hash = self.GENESIS
        for i, entry in enumerate(entries):
            seq = entry.get("sequence", i + 1)

            # Verify prev_hash linkage
            if entry.get("prev_hash") != prev_hash:
                return {
                    "valid": False,
                    "total_entries": len(entries),
                    "first_broken_at": seq,
                    "error": (
                        f"Chain broken at sequence {seq}: "
                        f"prev_hash mismatch. Expected {prev_hash!r}, "
                        f"got {entry.get('prev_hash')!r}"
                    ),
                }

            # Recompute HMAC
            stored_hmac = entry.pop("entry_hash", "")
            entry_json = json.dumps(
                {**entry, "entry_hash": ""},
                sort_keys=True,
                separators=(",", ":"),
            )
            computed_hmac = hmac.new(
                self.hmac_key,
                entry_json.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            entry["entry_hash"] = stored_hmac  # Restore

            if not hmac.compare_digest(computed_hmac, stored_hmac):
                return {
                    "valid": False,
                    "total_entries": len(entries),
                    "first_broken_at": seq,
                    "error": f"HMAC mismatch at sequence {seq}: entry has been tampered.",
                }

            prev_hash = stored_hmac

        return {
            "valid": True,
            "total_entries": len(entries),
            "first_broken_at": None,
            "error": None,
        }

    def read_entries(self, limit: int = 100, offset: int = 0) -> List[dict]:
        """Read log entries with optional pagination."""
        if not self.log_path.exists():
            return []
        entries = []
        with open(self.log_path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                if i < offset:
                    continue
                if len(entries) >= limit:
                    break
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return entries

    # ---------------------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------------------

    def _load_last_hash(self) -> str:
        """Read the entry_hash of the last log entry for chain continuity."""
        if not self.log_path.exists():
            return self.GENESIS
        last_line = ""
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last_line = line.strip()
        if not last_line:
            return self.GENESIS
        try:
            return json.loads(last_line).get("entry_hash", self.GENESIS)
        except Exception:
            return self.GENESIS

    def _load_last_sequence(self) -> int:
        """Read the sequence number of the last log entry."""
        if not self.log_path.exists():
            return 0
        last_line = ""
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last_line = line.strip()
        if not last_line:
            return 0
        try:
            return json.loads(last_line).get("sequence", 0)
        except Exception:
            return 0

    def _rotate_log(self):
        """Rotate the current log file by appending a timestamp to its name."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        rotated_name = self.log_path.stem + f"_{timestamp}" + self.log_path.suffix
        rotated_path = self.log_dir / rotated_name
        self.log_path.rename(rotated_path)
        # Reset chain for new log file, but record the rotation event
        self._last_hash = self.GENESIS
        self._sequence = 0

    def _load_or_generate_key(self) -> bytes:
        """
        Load HMAC key from a key file, or generate and store a new one.
        Key file is stored with 0600 permissions.
        In production, this key should come from KeyManager / OS keychain.
        """
        key_path = self.log_dir / ".audit_hmac_key"
        if key_path.exists():
            with open(key_path, "rb") as f:
                return f.read()
        else:
            import secrets
            key = secrets.token_bytes(32)
            with open(key_path, "wb") as f:
                f.write(key)
            if os.name == "posix":
                os.chmod(key_path, 0o600)
            return key

    def _default_log_dir(self) -> Path:
        """Return OS-appropriate log directory."""
        if os.name == "nt":
            base = os.getenv("PROGRAMDATA", "C:\\ProgramData")
            return Path(base) / "SecureErasePro" / "logs"
        elif os.name == "posix":
            return Path("/var/log/secureerase")
        else:
            return Path.home() / ".secureerase" / "logs"


# Allow Union type hint in method signatures
from typing import Union
