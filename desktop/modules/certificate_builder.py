"""
=============================================================================
Module: CertificateBuilder
Purpose: Assemble the complete, structured JSON certificate from all
         operation data. Produces a canonical, signable dict that maps
         every field to at least one compliance standard per Phase 4 schema.
         Also computes the audit chain linkage (previous certificate hash).
Inputs:  FileEntry metadata, WipeResult, HashResult (pre+post),
         ComplianceMapping[], operator context dict, app config
Outputs: Unsigned certificate dict (signature.value = "")
         Canonical JSON bytes (ready for signing)
Dependencies: uuid, datetime, json, hashlib (stdlib)
Compliance: All frameworks — certificate is the primary evidence artifact
=============================================================================
"""

import hashlib
import json
import platform
import socket
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Union

from .hash_verifier import HashResult
from .secure_wipe_engine import WipeResult
from .compliance_mapper import ComplianceMapping


@dataclass
class FileEntry:
    """
    Metadata about the target file or folder.
    Collected by FileScanner before the wipe operation begins.
    """
    path: str
    type: str          # "file" | "folder"
    size_bytes: int
    file_count: int    # 1 for files, N for folders
    is_ssd: bool = False
    device_type: str = "HDD"   # 'HDD' | 'SSD' | 'NVMe' | 'unknown'
    filesystem: str = "unknown"


class CertificateBuilder:
    """
    Assembles the complete JSON certificate per Phase 4 schema.

    Design decisions:
    - The builder pattern keeps assembly separate from signing, so
      DigitalSigner receives a clean, complete, canonical dict.
    - canonical_serialize() uses json.dumps with sort_keys=True and
      no whitespace — this produces identical bytes on any platform,
      which is mandatory for cross-platform signature verification.
    - The audit chain links each certificate to the previous one via
      SHA-256 hash, creating a tamper-evident chain. Breaking this chain
      (by deleting or modifying a certificate) is detectable during audit.
    - operator.ip_address is included per compliance requirements but
      is redacted in the Tier 1 public portal response.
    """

    SCHEMA_VERSION = "1.0"
    APP_VERSION = "0.1.0"

    def __init__(
        self,
        organization: str,
        portal_domain: str,
        public_key_url: str,
        public_key_fingerprint: str,
    ):
        """
        Args:
            organization: Issuing organization name (from enterprise config).
            portal_domain: Base URL of the verification portal.
            public_key_url: Full URL where the public key PEM can be fetched.
            public_key_fingerprint: SHA-256 hex of the public key DER.
        """
        self.organization = organization
        self.portal_domain = portal_domain.rstrip("/")
        self.public_key_url = public_key_url
        self.public_key_fingerprint = public_key_fingerprint

    def build(
        self,
        file_entry: FileEntry,
        wipe_result: WipeResult,
        hash_before: HashResult,
        hash_after: HashResult,
        compliance_mappings: List[ComplianceMapping],
        operator_username: Optional[str] = None,
        previous_cert_json: Optional[str] = None,
        chain_position: int = 1,
    ) -> dict:
        """
        Assemble the complete unsigned certificate dict.

        Args:
            file_entry: Metadata about the target file/folder.
            wipe_result: Output from SecureWipeEngine or SSDHandler.
            hash_before: Pre-wipe HashResult.
            hash_after: Post-wipe HashResult.
            compliance_mappings: Output from ComplianceMapper.
            operator_username: OS username of the operator (optional override).
            previous_cert_json: Canonical JSON of the previous certificate
                                for audit chain linkage. None for first cert.
            chain_position: 1-indexed position in the audit chain.

        Returns:
            Complete certificate dict with signature.value = "" (unsigned).
        """
        cert_id = str(uuid.uuid4())
        generated_at = datetime.now(timezone.utc).isoformat()

        # Resolve operator context from the running environment
        username = operator_username or self._get_username()
        hostname = self._get_hostname()
        ip_address = self._get_local_ip()
        os_info = self._get_os_info()

        # Compute audit chain hash
        if previous_cert_json:
            prev_hash = hashlib.sha256(
                previous_cert_json.encode("utf-8")
            ).hexdigest()
        else:
            prev_hash = "GENESIS"

        cert = {
            "certificate_id": cert_id,
            "schema_version": self.SCHEMA_VERSION,
            "issuer": {
                "organization": self.organization,
                "portal_verification_url": (
                    f"{self.portal_domain}/cert/{cert_id}"
                ),
                "public_key_url": self.public_key_url,
                "public_key_fingerprint": self.public_key_fingerprint,
            },
            "generated_at": generated_at,
            "operator": {
                "username": username,
                "hostname": hostname,
                "ip_address": ip_address,
                "os": os_info,
                "app_version": self.APP_VERSION,
            },
            "target": {
                "path": file_entry.path,
                "type": file_entry.type,
                "size_bytes": file_entry.size_bytes,
                "file_count": file_entry.file_count,
                "sha256_before": hash_before.sha256,
                "sha3_256_before": hash_before.sha3_256,
                "device_type": file_entry.device_type,
                "filesystem": file_entry.filesystem,
            },
            "wipe_operation": {
                "standard_applied": wipe_result.standard_applied,
                "passes_completed": wipe_result.passes_completed,
                "passes_total": wipe_result.passes_total,
                "pass_detail": [
                    {
                        "pass_number": p.pass_number,
                        "pattern": p.pattern,
                        "verified": p.verified,
                        "started_at": p.started_at,
                        "completed_at": p.completed_at,
                        **({"error": p.error} if p.error else {}),
                    }
                    for p in wipe_result.pass_detail
                ],
                "duration_seconds": wipe_result.duration_seconds,
                "verified": wipe_result.verified,
                "sha256_after": hash_after.sha256,
                "sha3_256_after": hash_after.sha3_256,
                **({"error": wipe_result.error} if wipe_result.error else {}),
            },
            "compliance_mapping": [
                m.to_dict() for m in compliance_mappings
            ],
            "registry": {
                "registered": False,
                "registry_url": "",
                "registered_at": "",
            },
            "audit_chain": {
                "previous_certificate_hash": prev_hash,
                "chain_position": chain_position,
            },
            # Signature block — value is empty until DigitalSigner fills it
            "signature": {
                "algorithm": "",          # Set by DigitalSigner
                "public_key_fingerprint": self.public_key_fingerprint,
                "signed_at": "",          # Set by DigitalSigner
                "value": "",              # Set by DigitalSigner
            },
        }

        return cert

    def canonical_serialize(self, cert: dict) -> bytes:
        """
        Produce canonical JSON bytes for signing or hashing.

        Rules per Phase 4:
        1. signature.value MUST be "" (empty string) before serialization.
           If it is not, this method raises ValueError to prevent accidentally
           signing a cert with a pre-existing signature value (double-sign attack).
        2. json.dumps with sort_keys=True, separators=(',',':'), ensure_ascii=True.
        3. Encode as UTF-8.

        This method is used by:
        - DigitalSigner (before signing)
        - AuditLogger (when computing audit chain hash of previous cert)
        - VerificationEngine (portal, during offline verification)

        Returns:
            UTF-8 bytes of the canonical JSON representation.
        """
        sig_value = cert.get("signature", {}).get("value", "")
        if sig_value != "":
            raise ValueError(
                "CertificateBuilder.canonical_serialize: signature.value must be "
                "empty string '' before canonicalization. Got a non-empty value. "
                "This prevents double-signing. Clear the value before serializing."
            )

        return json.dumps(
            cert,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")

    # ---------------------------------------------------------------------------
    # Operator context helpers
    # ---------------------------------------------------------------------------

    def _get_username(self) -> str:
        try:
            import os
            return os.getenv("USERNAME") or os.getenv("USER") or "unknown"
        except Exception:
            return "unknown"

    def _get_hostname(self) -> str:
        try:
            return socket.gethostname()
        except Exception:
            return "unknown"

    def _get_local_ip(self) -> str:
        try:
            # Connect to an external address (doesn't send data) to determine
            # the local interface IP. Falls back gracefully if offline.
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _get_os_info(self) -> str:
        try:
            return f"{platform.system()} {platform.release()} ({platform.machine()})"
        except Exception:
            return "unknown"


# ---------------------------------------------------------------------------
# Module-level convenience functions for test and external use.
# These accept plain dicts OR dataclass instances, making them usable
# directly in tests without constructing full dataclass objects.
# ---------------------------------------------------------------------------

def _to_obj(cls, val):
    """Convert a dict to a dataclass instance if needed."""
    if isinstance(val, dict):
        # Filter to only keys that exist in the dataclass
        import dataclasses
        fields = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in val.items() if k in fields})
    return val


def build_certificate(
    file_entry,
    wipe_result,
    hash_before,
    hash_after=None,
    compliance_mappings=None,
    operator_username=None,
    operator=None,
    previous_cert_json=None,
    chain_position: int = 1,
    issuer_org: str = "SecureErase Pro",
    portal_url: str = "https://verify.example.com",
    public_key_url: str = "https://verify.example.com/api/v1/keys/default",
    public_key_fingerprint: str = "0" * 64,
) -> dict:
    """
    Module-level builder: build an unsigned certificate dict.
    Accepts plain dicts or dataclass instances for all inputs.
    Extra kwargs (issuer_org, portal_url, etc.) allow per-call configuration.
    """
    from .hash_verifier import HashResult as HR
    from .secure_wipe_engine import WipeResult as WR, PassDetail as PD
    from .compliance_mapper import ComplianceMapping as CM

    builder = CertificateBuilder(
        organization=issuer_org,
        portal_domain=portal_url,
        public_key_url=public_key_url,
        public_key_fingerprint=public_key_fingerprint,
    )

    # Coerce dicts → dataclasses
    fe = _to_obj(FileEntry, file_entry)

    # WipeResult may have pass_detail as list of dicts
    if isinstance(wipe_result, dict):
        wr_dict = dict(wipe_result)
        pd_raw = wr_dict.pop("pass_detail", [])
        pd_list = []
        for p in pd_raw:
            if isinstance(p, dict):
                pd_dict = dict(p)
                pd_dict.setdefault("started_at", "")
                pd_dict.setdefault("completed_at", "")
                pd_dict.setdefault("error", None)
                pd_list.append(_to_obj(PD, pd_dict))
            else:
                pd_list.append(p)
        # Fill in required WipeResult fields that may be absent in test dicts
        import dataclasses
        wr_fields = {f.name for f in dataclasses.fields(WR)}
        wr_kwargs = {k: v for k, v in wr_dict.items() if k in wr_fields}
        wr_kwargs.setdefault("passes_total", wr_kwargs.get("passes_completed", 0))
        wr_kwargs.setdefault("duration_seconds", 0.0)
        wr_kwargs.setdefault("verified", True)
        wr_kwargs.setdefault("sha256_after", "")
        wr_kwargs.setdefault("sha3_256_after", "")
        wr_kwargs["pass_detail"] = pd_list
        wr = WR(**wr_kwargs)
    else:
        wr = wipe_result

    def _coerce_hash(d):
        """Convert a dict to HashResult, filling in missing optional fields."""
        if not isinstance(d, dict):
            return d
        defaults = {"size_bytes": 0, "computed_at": "", "elapsed_seconds": 0.0, "path": None, "error": None}
        return HR(**{**defaults, **{k: v for k, v in d.items() if k in {f.name for f in __import__('dataclasses').fields(HR)}}})

    hb = _coerce_hash(hash_before) if hash_before else HR(
        sha256="0"*64, sha3_256="0"*64, size_bytes=0,
        computed_at="", elapsed_seconds=0.0)
    ha = _coerce_hash(hash_after) if hash_after else HR(
        sha256="0"*64, sha3_256="0"*64, size_bytes=0,
        computed_at="", elapsed_seconds=0.0)

    if compliance_mappings is None:
        compliance_mappings = []
    cm_list = [_to_obj(CM, c) for c in compliance_mappings]

    # Operator username override
    op_user = operator_username
    if operator and isinstance(operator, dict):
        op_user = op_user or operator.get("username")

    return builder.build(
        file_entry=fe,
        wipe_result=wr,
        hash_before=hb,
        hash_after=ha,
        compliance_mappings=cm_list,
        operator_username=op_user,
        previous_cert_json=previous_cert_json,
        chain_position=chain_position,
    )


def canonical_serialize(cert: dict) -> bytes:
    """Module-level wrapper: produce canonical UTF-8 JSON bytes for signing."""
    import json
    c = dict(cert)
    c.setdefault("signature", {})
    c["signature"] = dict(c["signature"])
    c["signature"]["value"] = ""
    return json.dumps(c, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
