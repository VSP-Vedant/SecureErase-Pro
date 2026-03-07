"""
=============================================================================
Module: RegistryClient
Purpose: Upload signed certificate metadata to the verification portal
         registry via HTTPS REST API. Implements a local retry queue using
         SQLite for offline-first reliability — certificates are fully valid
         (signed) even if registration never succeeds.
Inputs:  Signed certificate dict, portal API URL, API key
Outputs: RegistrationResult; queued SQLite record on failure
Dependencies: httpx (pip), sqlite3 (stdlib)
Compliance:
  - Enables online verification per all Phase 2 frameworks that require
    third-party or portal-accessible verification records
=============================================================================
"""

import json
import sqlite3
import time
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import os

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


@dataclass
class RegistrationResult:
    """Result of a certificate registration attempt."""
    registered: bool
    registry_url: str
    registered_at: str
    queued: bool = False       # True if registration failed and was queued for retry
    queue_id: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


class RegistryClient:
    """
    Uploads certificate metadata to the verification portal.

    Design:
    - Uses httpx for async-capable HTTPS requests with connection pooling.
    - On upload failure, the certificate is stored in a local SQLite queue.
    - A background thread (started by UIController) calls retry_pending()
      periodically with exponential backoff.
    - The certificate's 'registry' block is updated in-place with the
      registration result — the signed JSON signature ONLY covers the cert
      at the moment of signing (before registry info was populated), so
      updating registry fields does NOT invalidate the JSON signature.
      The PDF must be regenerated after registration if registry info
      should appear in the PDF.

    Security:
    - API key is transmitted in the Authorization header (Bearer scheme),
      never in query parameters (would appear in server access logs).
    - TLS certificate validation is enabled by default. Disable only for
      self-hosted portals with self-signed certs (set verify_ssl=False).
    - mTLS is supported by providing client_cert_path and client_key_path.
    - The SQLite queue stores the full signed JSON — it must be stored
      in a protected directory (same as audit logs).
    """

    RETRY_DELAYS = [60, 300, 900, 3600, 14400]  # seconds: 1m, 5m, 15m, 1h, 4h

    def __init__(
        self,
        api_url: str,
        api_key: str,
        queue_db_path: Optional[str] = None,
        verify_ssl: bool = True,
        client_cert_path: Optional[str] = None,
        client_key_path: Optional[str] = None,
        timeout: float = 30.0,
    ):
        """
        Args:
            api_url: Base URL of the portal API (e.g. https://verify.example.com/api/v1).
            api_key: Bearer token for portal authentication.
            queue_db_path: Path to SQLite queue database. Defaults to ~/.secureerase/queue.db.
            verify_ssl: Verify TLS certificates (default True).
            client_cert_path: Path to client certificate for mTLS.
            client_key_path: Path to client private key for mTLS.
            timeout: Request timeout in seconds.
        """
        if not HAS_HTTPX:
            raise ImportError("RegistryClient requires: pip install httpx")

        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        # mTLS configuration
        self.client_cert = None
        if client_cert_path and client_key_path:
            self.client_cert = (client_cert_path, client_key_path)

        # SQLite retry queue
        if queue_db_path is None:
            queue_db_path = str(Path.home() / ".secureerase" / "registry_queue.db")
        Path(queue_db_path).parent.mkdir(parents=True, exist_ok=True)
        self.queue_db_path = queue_db_path
        self._init_queue_db()

    def register(self, cert: dict) -> RegistrationResult:
        """
        Upload a signed certificate to the portal registry.

        The uploaded payload is the full signed JSON certificate.
        The portal stores only the metadata it needs for verification;
        sensitive fields (file paths, operator details) are stored
        encrypted and only accessible to authenticated enterprise users.

        Args:
            cert: Signed certificate dict (signature.value must be populated).

        Returns:
            RegistrationResult with registration details.
        """
        cert_id = cert.get("certificate_id", "unknown")

        if not cert.get("signature", {}).get("value"):
            raise ValueError(
                "RegistryClient.register: certificate is not signed. "
                "Sign with DigitalSigner before registering."
            )

        payload = json.dumps(cert, sort_keys=True, separators=(",", ":"))
        endpoint = f"{self.api_url}/registry/register"

        try:
            client_kwargs = {
                "verify": self.verify_ssl,
                "timeout": self.timeout,
            }
            if self.client_cert:
                client_kwargs["cert"] = self.client_cert

            with httpx.Client(**client_kwargs) as client:
                response = client.post(
                    endpoint,
                    content=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {self.api_key}",
                        "X-SecureErase-Version": "0.1.0",
                    },
                )

            if response.status_code == 200:
                data = response.json()
                registry_url = data.get(
                    "registry_url",
                    f"{self.api_url.replace('/api/v1', '')}/cert/{cert_id}"
                )
                registered_at = data.get(
                    "registered_at",
                    datetime.now(timezone.utc).isoformat()
                )
                return RegistrationResult(
                    registered=True,
                    registry_url=registry_url,
                    registered_at=registered_at,
                )

            elif response.status_code == 409:
                # Certificate already registered (idempotent)
                data = response.json()
                return RegistrationResult(
                    registered=True,
                    registry_url=data.get("registry_url", ""),
                    registered_at=data.get("registered_at", ""),
                    error="Certificate already registered (duplicate upload ignored)",
                )

            else:
                error_msg = f"HTTP {response.status_code}: {response.text[:200]}"
                return self._queue_cert(cert_id, payload, error_msg)

        except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as exc:
            return self._queue_cert(cert_id, payload, str(exc))

    def retry_pending(self, max_retries: int = 5) -> dict:
        """
        Attempt to register all queued certificates.
        Called periodically by a background thread in UIController.

        Returns:
            Summary dict with 'attempted', 'succeeded', 'still_pending'.
        """
        summary = {"attempted": 0, "succeeded": 0, "still_pending": 0}
        pending = self._get_pending_queue()

        for record in pending:
            queue_id = record["queue_id"]
            cert_json = record["cert_json"]
            attempts = record["attempts"]

            if attempts >= max_retries:
                summary["still_pending"] += 1
                continue

            summary["attempted"] += 1
            try:
                cert = json.loads(cert_json)
                result = self.register(cert)

                if result.registered and not result.queued:
                    self._remove_from_queue(queue_id)
                    summary["succeeded"] += 1
                else:
                    self._increment_attempts(queue_id)
                    summary["still_pending"] += 1

            except Exception:
                self._increment_attempts(queue_id)
                summary["still_pending"] += 1

        return summary

    def get_queue_count(self) -> int:
        """Return count of pending registrations in the queue."""
        conn = sqlite3.connect(self.queue_db_path)
        try:
            cursor = conn.execute("SELECT COUNT(*) FROM registry_queue")
            return cursor.fetchone()[0]
        finally:
            conn.close()

    # ---------------------------------------------------------------------------
    # SQLite queue helpers
    # ---------------------------------------------------------------------------

    def _init_queue_db(self):
        conn = sqlite3.connect(self.queue_db_path)
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS registry_queue (
                    queue_id TEXT PRIMARY KEY,
                    cert_id TEXT NOT NULL,
                    cert_json TEXT NOT NULL,
                    queued_at TEXT NOT NULL,
                    attempts INTEGER DEFAULT 0,
                    last_attempt_at TEXT
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def _queue_cert(self, cert_id: str, cert_json: str, error: str) -> RegistrationResult:
        queue_id = str(uuid.uuid4())
        queued_at = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect(self.queue_db_path)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO registry_queue "
                "(queue_id, cert_id, cert_json, queued_at) VALUES (?,?,?,?)",
                (queue_id, cert_id, cert_json, queued_at)
            )
            conn.commit()
        finally:
            conn.close()

        return RegistrationResult(
            registered=False,
            registry_url="",
            registered_at="",
            queued=True,
            queue_id=queue_id,
            error=f"Registration failed — queued for retry. Error: {error}",
        )

    def _get_pending_queue(self) -> list:
        conn = sqlite3.connect(self.queue_db_path)
        try:
            cursor = conn.execute(
                "SELECT queue_id, cert_id, cert_json, attempts FROM registry_queue "
                "ORDER BY queued_at ASC"
            )
            return [
                {"queue_id": r[0], "cert_id": r[1], "cert_json": r[2], "attempts": r[3]}
                for r in cursor.fetchall()
            ]
        finally:
            conn.close()

    def _remove_from_queue(self, queue_id: str):
        conn = sqlite3.connect(self.queue_db_path)
        try:
            conn.execute("DELETE FROM registry_queue WHERE queue_id = ?", (queue_id,))
            conn.commit()
        finally:
            conn.close()

    def _increment_attempts(self, queue_id: str):
        conn = sqlite3.connect(self.queue_db_path)
        try:
            conn.execute(
                "UPDATE registry_queue SET attempts = attempts + 1, "
                "last_attempt_at = ? WHERE queue_id = ?",
                (datetime.now(timezone.utc).isoformat(), queue_id)
            )
            conn.commit()
        finally:
            conn.close()
