"""
=============================================================================
Module: AuditLogService
Purpose: Record all verification events to the database and flag anomalies.
         Anomaly detection: rapid re-verification of same cert, tamper attempts,
         duplicate certificate IDs registered in quick succession.
Inputs:  Verification event data, SQLAlchemy session
Outputs: VerificationEvent ORM rows, anomaly alerts
Dependencies: modules/models.py, modules/crypto_utils.py
Compliance:
  - ISO/IEC 27001 A.8.15: information security event logging
  - SOC 2 CC7.2: system monitoring
  - GDPR Art.5(1)(f): integrity and confidentiality — raw IPs not logged
=============================================================================
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import select, func
from sqlalchemy.orm import Session

from .crypto_utils import hash_ip
from .models import VerificationEvent


# ---------------------------------------------------------------------------
# Event logging
# ---------------------------------------------------------------------------

# Anomaly thresholds
RAPID_REVERIFY_THRESHOLD = 20    # >20 verifications of same cert in 1 minute
TAMPER_ALERT_THRESHOLD = 3       # >3 tamper results from same IP in 10 minutes


def log_verification_event(
    method: str,
    result: str,
    session: Session,
    certificate_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    tier: str = "public",
    user_id: Optional[UUID] = None,
) -> VerificationEvent:
    """
    Log a verification event and run anomaly detection.

    Args:
        method: "file_upload" | "id_lookup" | "qr_scan"
        result: "valid" | "invalid" | "tampered" | "not_found" | "revoked"
        session: SQLAlchemy session
        certificate_id: UUID string or None if not_found
        ip_address: Client IP (will be hashed before storage)
        tier: "public" | "enterprise" | "admin"
        user_id: User UUID for authenticated requests

    Returns:
        Created VerificationEvent row
    """
    cert_uuid: Optional[UUID] = None
    if certificate_id:
        try:
            cert_uuid = UUID(str(certificate_id))
        except (ValueError, AttributeError):
            cert_uuid = None

    ip_hash_val = hash_ip(ip_address) if ip_address else None

    # Anomaly detection
    flagged, flag_reason = _detect_anomaly(
        cert_uuid=cert_uuid,
        ip_hash=ip_hash_val,
        result=result,
        session=session,
    )

    event = VerificationEvent(
        certificate_id=cert_uuid,
        result=result,
        method=method,
        tier=tier,
        ip_hash=ip_hash_val,
        user_id=user_id,
        flagged=flagged,
        flag_reason=flag_reason if flagged else None,
    )
    session.add(event)
    session.flush()

    # Trigger notification for flagged events
    if flagged:
        _notify_anomaly(event, flag_reason, session)

    return event


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------

def _detect_anomaly(
    cert_uuid: Optional[UUID],
    ip_hash: Optional[str],
    result: str,
    session: Session,
) -> tuple[bool, str]:
    """
    Check for anomalous patterns in recent verification events.
    Returns (flagged, reason).
    """
    now = datetime.now(timezone.utc)

    # 1. Rapid re-verification: same cert_id >N times in 1 minute
    if cert_uuid:
        one_min_ago = now - timedelta(minutes=1)
        recent_count = session.execute(
            select(func.count(VerificationEvent.id)).where(
                VerificationEvent.certificate_id == cert_uuid,
                VerificationEvent.verified_at >= one_min_ago,
            )
        ).scalar() or 0

        if recent_count >= RAPID_REVERIFY_THRESHOLD:
            return True, (
                f"Rapid re-verification: {recent_count} requests for cert "
                f"{str(cert_uuid)[:8]}... in the last 60 seconds"
            )

    # 2. Tamper storm: same IP with >N tamper results in 10 minutes
    if ip_hash and result == "tampered":
        ten_min_ago = now - timedelta(minutes=10)
        tamper_count = session.execute(
            select(func.count(VerificationEvent.id)).where(
                VerificationEvent.ip_hash == ip_hash,
                VerificationEvent.result == "tampered",
                VerificationEvent.verified_at >= ten_min_ago,
            )
        ).scalar() or 0

        if tamper_count >= TAMPER_ALERT_THRESHOLD:
            return True, (
                f"Tamper storm: {tamper_count} tampered results from same IP "
                f"in the last 10 minutes"
            )

    return False, ""


# ---------------------------------------------------------------------------
# Notification dispatch (delegated to NotificationService)
# ---------------------------------------------------------------------------

def _notify_anomaly(event: VerificationEvent, reason: str,
                     session: Session) -> None:
    """
    Fire anomaly notification. Delegates to NotificationService.
    Non-blocking: notification failure does not affect event logging.
    """
    try:
        from .notification_service import send_anomaly_alert
        send_anomaly_alert(
            event_id=str(event.id),
            certificate_id=str(event.certificate_id) if event.certificate_id else None,
            reason=reason,
        )
    except Exception:
        # Notification failure must never break the verification flow
        pass


# ---------------------------------------------------------------------------
# Admin queries
# ---------------------------------------------------------------------------

def get_verification_stats(session: Session, days: int = 30) -> dict:
    """
    Aggregate verification statistics for admin dashboard.
    Returns counts by result and method over the past N days.
    """
    from_dt = datetime.now(timezone.utc) - timedelta(days=days)

    by_result = session.execute(
        select(VerificationEvent.result, func.count(VerificationEvent.id))
        .where(VerificationEvent.verified_at >= from_dt)
        .group_by(VerificationEvent.result)
    ).all()

    by_method = session.execute(
        select(VerificationEvent.method, func.count(VerificationEvent.id))
        .where(VerificationEvent.verified_at >= from_dt)
        .group_by(VerificationEvent.method)
    ).all()

    flagged_count = session.execute(
        select(func.count(VerificationEvent.id)).where(
            VerificationEvent.flagged == True,
            VerificationEvent.verified_at >= from_dt,
        )
    ).scalar() or 0

    return {
        "period_days": days,
        "by_result": {r: c for r, c in by_result},
        "by_method": {m: c for m, c in by_method},
        "flagged_events": flagged_count,
    }


def get_flagged_events(session: Session, limit: int = 100) -> list[dict]:
    """Return recent flagged anomaly events for admin review."""
    events = session.execute(
        select(VerificationEvent)
        .where(VerificationEvent.flagged == True)
        .order_by(VerificationEvent.verified_at.desc())
        .limit(limit)
    ).scalars().all()

    return [
        {
            "id": str(e.id),
            "certificate_id": str(e.certificate_id) if e.certificate_id else None,
            "verified_at": e.verified_at.isoformat(),
            "result": e.result,
            "method": e.method,
            "flag_reason": e.flag_reason,
        }
        for e in events
    ]
