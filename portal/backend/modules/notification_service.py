"""
=============================================================================
Module: NotificationService
Purpose: Send email alerts for anomaly detection events, tamper attempts,
         and system alerts (key rotation reminders, failed verifications
         above threshold). Non-blocking — all sends are best-effort.
Inputs:  Event data dicts, SMTP config from environment
Outputs: Email delivery (fire-and-forget with logging)
Dependencies: smtplib, email, os, logging
Security:
  - SMTP credentials loaded from environment only — never hardcoded
  - TLS enforced (STARTTLS or SMTPS)
  - No sensitive certificate data included in notification emails
    (only certificate ID prefix and event type)
=============================================================================
"""

import logging
import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SMTP configuration
# ---------------------------------------------------------------------------

def _get_smtp_config() -> dict:
    return {
        "host": os.environ.get("SMTP_HOST", ""),
        "port": int(os.environ.get("SMTP_PORT", "587")),
        "user": os.environ.get("SMTP_USER", ""),
        "password": os.environ.get("SMTP_PASSWORD", ""),
        "from_email": os.environ.get("NOTIFICATION_FROM_EMAIL", ""),
        "admin_email": os.environ.get("ADMIN_EMAIL", ""),
    }


def _smtp_available() -> bool:
    cfg = _get_smtp_config()
    return bool(cfg["host"] and cfg["user"] and cfg["password"]
                 and cfg["from_email"] and cfg["admin_email"])


def _send_email(to: str, subject: str, body_html: str, body_text: str) -> None:
    """
    Send an email via SMTP with STARTTLS.
    Raises on failure — callers should catch and log.
    """
    cfg = _get_smtp_config()

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = cfg["from_email"]
    msg["To"] = to

    msg.attach(MIMEText(body_text, "plain"))
    msg.attach(MIMEText(body_html, "html"))

    context = ssl.create_default_context()

    with smtplib.SMTP(cfg["host"], cfg["port"]) as server:
        server.ehlo()
        server.starttls(context=context)
        server.login(cfg["user"], cfg["password"])
        server.sendmail(cfg["from_email"], to, msg.as_string())


# ---------------------------------------------------------------------------
# Alert types
# ---------------------------------------------------------------------------

def send_anomaly_alert(
    event_id: str,
    certificate_id: Optional[str],
    reason: str,
) -> None:
    """
    Send anomaly alert to admin. Called by AuditLogService on flagged events.
    Non-blocking: failure is logged but not raised.
    """
    if not _smtp_available():
        logger.warning("SMTP not configured — anomaly alert not sent: %s", reason)
        return

    cfg = _get_smtp_config()
    cert_prefix = certificate_id[:8] + "..." if certificate_id else "N/A"

    subject = f"[SecureErase Pro] Anomaly Detected — {reason[:60]}"
    body_text = (
        f"SecureErase Pro Portal — Anomaly Alert\n\n"
        f"Event ID: {event_id}\n"
        f"Certificate ID: {cert_prefix}\n"
        f"Reason: {reason}\n\n"
        f"Review flagged events in the Admin Dashboard.\n"
    )
    body_html = f"""
    <html><body>
    <h2 style="color:#c0392b">SecureErase Pro — Anomaly Alert</h2>
    <table>
      <tr><td><b>Event ID</b></td><td>{event_id}</td></tr>
      <tr><td><b>Certificate ID</b></td><td>{cert_prefix}</td></tr>
      <tr><td><b>Reason</b></td><td>{reason}</td></tr>
    </table>
    <p>Review flagged events in the <a href="#">Admin Dashboard</a>.</p>
    </body></html>
    """

    try:
        _send_email(cfg["admin_email"], subject, body_html, body_text)
        logger.info("Anomaly alert sent for event %s", event_id)
    except Exception as e:
        logger.error("Failed to send anomaly alert: %s", e)


def send_key_rotation_reminder(fingerprint: str, created_days_ago: int) -> None:
    """
    Remind admin that a signing key is aging and should be rotated.
    """
    if not _smtp_available():
        return

    cfg = _get_smtp_config()
    subject = f"[SecureErase Pro] Signing Key Rotation Reminder"
    body_text = (
        f"The signing key {fingerprint[:16]}... was created {created_days_ago} days ago.\n"
        f"Consider rotating signing keys annually per your key management policy.\n"
        f"Use the Admin Dashboard → Key Management to rotate.\n"
    )
    body_html = f"""
    <html><body>
    <h2>SecureErase Pro — Key Rotation Reminder</h2>
    <p>Signing key <code>{fingerprint[:16]}...</code> is {created_days_ago} days old.</p>
    <p>Review your key rotation policy and rotate if due.</p>
    </body></html>
    """

    try:
        _send_email(cfg["admin_email"], subject, body_html, body_text)
    except Exception as e:
        logger.error("Failed to send key rotation reminder: %s", e)


def send_tamper_alert(certificate_id: str, count: int) -> None:
    """
    Alert admin when multiple tamper attempts are detected for one certificate.
    """
    if not _smtp_available():
        return

    cfg = _get_smtp_config()
    cert_prefix = certificate_id[:8] + "..."
    subject = f"[SecureErase Pro] Tamper Attempts Detected — Cert {cert_prefix}"
    body_text = (
        f"Certificate {cert_prefix} has received {count} tamper detection results "
        f"in a short period.\nThis may indicate an active forgery or manipulation attempt.\n"
        f"Review the certificate in the Admin Dashboard.\n"
    )
    body_html = f"""
    <html><body>
    <h2 style="color:#c0392b">SecureErase Pro — Tamper Alert</h2>
    <p>Certificate <code>{cert_prefix}</code> has received <b>{count}</b> tampered results.</p>
    <p>This may indicate an active forgery attempt. Review immediately.</p>
    </body></html>
    """

    try:
        _send_email(cfg["admin_email"], subject, body_html, body_text)
    except Exception as e:
        logger.error("Failed to send tamper alert: %s", e)
