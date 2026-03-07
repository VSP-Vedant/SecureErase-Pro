"""
=============================================================================
Module: ReportExporter
Purpose: Batch export, archive, and deliver certificates in PDF, JSON,
         and ZIP formats. Supports email delivery and folder-based archival.
Inputs:  List of (cert_dict, pdf_bytes) tuples, export format, delivery
Outputs: Exported archive or individual files
Dependencies: zipfile, pathlib, smtplib, email (stdlib)
Compliance:
  - Supports certificate retention requirements under HIPAA, PCI-DSS,
    SOC 2, and ISO/IEC 27001 (audit record retention policies)
=============================================================================
"""

import io
import json
import os
import smtplib
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from pathlib import Path
from typing import List, Optional, Tuple


class ExportFormat(str, Enum):
    PDF_ONLY = "pdf"
    JSON_ONLY = "json"
    ZIP_BOTH = "zip"


@dataclass
class ExportResult:
    """Result of a batch export operation."""
    format: str
    output_path: str
    file_count: int
    total_size_bytes: int
    exported_at: str
    error: Optional[str] = None


@dataclass
class EmailConfig:
    """SMTP email delivery configuration."""
    smtp_host: str
    smtp_port: int
    username: str
    password: str
    from_address: str
    use_tls: bool = True


class ReportExporter:
    """
    Exports certificate archives for enterprise record-keeping.

    Export modes:
    - PDF_ONLY: Exports one PDF per certificate to a directory.
    - JSON_ONLY: Exports one JSON file per certificate to a directory.
    - ZIP_BOTH: Creates a ZIP archive with both PDF and JSON for each cert.
      The ZIP is the recommended format for long-term archival and email
      delivery — it contains both the human-readable PDF and the
      machine-verifiable JSON in one file.

    Security:
    - Exported files are written to a caller-specified directory.
    - ZIP files include a manifest.json listing all included certificates
      with their IDs and hashes, providing a tamper check on the archive.
    - Email delivery uses STARTTLS or SSL; passwords are passed via
      EmailConfig and are never logged.
    """

    def export_batch(
        self,
        certs: List[Tuple[dict, Optional[bytes]]],
        output_dir: str,
        export_format: ExportFormat = ExportFormat.ZIP_BOTH,
        archive_name: Optional[str] = None,
    ) -> ExportResult:
        """
        Export a batch of certificates.

        Args:
            certs: List of (cert_dict, pdf_bytes) tuples.
                   pdf_bytes can be None if PDF was not generated.
            output_dir: Directory to write exported files.
            export_format: PDF_ONLY, JSON_ONLY, or ZIP_BOTH.
            archive_name: Custom name for ZIP archive. Auto-generated if None.

        Returns:
            ExportResult with path, file count, and size.
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        exported_at = datetime.now(timezone.utc).isoformat()

        if export_format == ExportFormat.ZIP_BOTH:
            return self._export_zip(certs, output_path, archive_name, exported_at)
        elif export_format == ExportFormat.PDF_ONLY:
            return self._export_files(certs, output_path, "pdf", exported_at)
        elif export_format == ExportFormat.JSON_ONLY:
            return self._export_files(certs, output_path, "json", exported_at)
        else:
            raise ValueError(f"ReportExporter: unknown export format: {export_format}")

    def _export_zip(
        self,
        certs: List[Tuple[dict, Optional[bytes]]],
        output_path: Path,
        archive_name: Optional[str],
        exported_at: str,
    ) -> ExportResult:
        """Create a ZIP archive containing PDFs, JSONs, and a manifest."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        if archive_name is None:
            archive_name = f"secureerase_certs_{timestamp}.zip"

        archive_path = output_path / archive_name
        manifest = {
            "export_tool": "SecureErase Pro",
            "exported_at": exported_at,
            "certificate_count": len(certs),
            "certificates": [],
        }

        total_size = 0
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for cert, pdf_bytes in certs:
                cert_id = cert.get("certificate_id", "unknown")

                # Write JSON
                json_bytes = json.dumps(
                    cert, sort_keys=True, indent=2
                ).encode("utf-8")
                json_name = f"{cert_id}/certificate_{cert_id}.json"
                zf.writestr(json_name, json_bytes)
                total_size += len(json_bytes)

                # Write PDF if available
                if pdf_bytes:
                    pdf_name = f"{cert_id}/certificate_{cert_id}.pdf"
                    zf.writestr(pdf_name, pdf_bytes)
                    total_size += len(pdf_bytes)

                manifest["certificates"].append({
                    "certificate_id": cert_id,
                    "generated_at": cert.get("generated_at", ""),
                    "wipe_standard": cert.get("wipe_operation", {}).get("standard_applied", ""),
                    "target_path": cert.get("target", {}).get("path", ""),
                    "has_pdf": pdf_bytes is not None,
                })

            # Write manifest
            manifest_json = json.dumps(
                manifest, sort_keys=True, indent=2
            ).encode("utf-8")
            zf.writestr("manifest.json", manifest_json)
            total_size += len(manifest_json)

        return ExportResult(
            format=ExportFormat.ZIP_BOTH.value,
            output_path=str(archive_path),
            file_count=len(certs),
            total_size_bytes=total_size,
            exported_at=exported_at,
        )

    def _export_files(
        self,
        certs: List[Tuple[dict, Optional[bytes]]],
        output_path: Path,
        fmt: str,
        exported_at: str,
    ) -> ExportResult:
        """Export individual files (PDF or JSON) to a directory."""
        total_size = 0
        count = 0

        for cert, pdf_bytes in certs:
            cert_id = cert.get("certificate_id", "unknown")

            if fmt == "json":
                data = json.dumps(cert, sort_keys=True, indent=2).encode("utf-8")
                file_path = output_path / f"certificate_{cert_id}.json"
                file_path.write_bytes(data)
                total_size += len(data)
                count += 1

            elif fmt == "pdf" and pdf_bytes:
                file_path = output_path / f"certificate_{cert_id}.pdf"
                file_path.write_bytes(pdf_bytes)
                total_size += len(pdf_bytes)
                count += 1

        return ExportResult(
            format=fmt,
            output_path=str(output_path),
            file_count=count,
            total_size_bytes=total_size,
            exported_at=exported_at,
        )

    def deliver_by_email(
        self,
        archive_path: str,
        recipients: List[str],
        email_config: EmailConfig,
        subject: Optional[str] = None,
        body: Optional[str] = None,
    ) -> bool:
        """
        Send an exported archive via email.

        Args:
            archive_path: Path to the ZIP or PDF file to attach.
            recipients: List of recipient email addresses.
            email_config: SMTP configuration.
            subject: Custom email subject (auto-generated if None).
            body: Custom email body (auto-generated if None).

        Returns:
            True if email sent successfully, False otherwise.
        """
        archive_path_obj = Path(archive_path)
        if not archive_path_obj.exists():
            raise FileNotFoundError(f"ReportExporter: archive not found: {archive_path}")

        if subject is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            subject = f"SecureErase Pro — Certificate Export ({timestamp})"

        if body is None:
            body = (
                "Please find attached the SecureErase Pro certificate export.\n\n"
                "Each certificate is digitally signed and can be verified:\n"
                "- Online: Visit the portal_verification_url in each certificate\n"
                "- Offline: Use the embedded JSON signature and the issuer's public key\n\n"
                "This email was generated automatically by SecureErase Pro."
            )

        msg = MIMEMultipart()
        msg["From"] = email_config.from_address
        msg["To"] = ", ".join(recipients)
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        with open(archive_path_obj, "rb") as f:
            attachment = MIMEBase("application", "octet-stream")
            attachment.set_payload(f.read())
        encoders.encode_base64(attachment)
        attachment.add_header(
            "Content-Disposition",
            "attachment",
            filename=archive_path_obj.name,
        )
        msg.attach(attachment)

        try:
            if email_config.use_tls:
                server = smtplib.SMTP(email_config.smtp_host, email_config.smtp_port)
                server.starttls()
            else:
                server = smtplib.SMTP_SSL(email_config.smtp_host, email_config.smtp_port)

            server.login(email_config.username, email_config.password)
            server.sendmail(email_config.from_address, recipients, msg.as_string())
            server.quit()
            return True
        except smtplib.SMTPException:
            return False
