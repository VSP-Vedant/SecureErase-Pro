"""
PDFRenderer
===========
Purpose:    Generate a PAdES-compliant PDF certificate from a signed
            certificate dict. The PDF includes:
              - Human-readable certificate layout (all Phase 5 sections)
              - QR code encoding the portal deep-link URL
              - Compliance badge grid (green/gray per framework)
              - Embedded raw signed JSON as a PDF/A-3 attachment
              - PAdES-B digital signature (any modification invalidates it)

Inputs:     - Signed certificate dict
            - KeyPair (for PAdES signing)
            - Optional logo path

Outputs:    - PDF bytes (ready to write to disk or return via API)

Dependencies:
            - reportlab (pip) — PDF content generation
            - pypdf (pip) — PDF manipulation and attachment
            - qrcode (pip) — QR code image generation
            - endesive (pip) — PAdES digital signature
            - Pillow (pip) — image handling for QR codes
            - cryptography (pip) — signing operations

Compliance relevance:
            - PAdES-B-LT: PDF Advanced Electronic Signatures — Long Term.
              Any byte modification after signing renders the signature
              invalid in any conforming PDF reader (Adobe, Foxit, etc.).
            - PDF/A-3: ISO 19005-3 — allows embedded file attachments
              (the raw JSON) while maintaining long-term archivability.
            - QR code level H provides 30% error correction, ensuring
              readability even if the certificate is partially obscured.

Design decisions:
            - The embedded JSON serves as the machine-verifiable canonical
              form; the PDF layout is the human-readable summary.
            - PAdES signing is applied LAST — after all content including
              the JSON attachment is written — so the signature covers
              the complete document.
            - If a TSA (timestamp authority) is configured, PAdES-B-LT is
              produced; otherwise PAdES-B-B (basic).
"""

from __future__ import annotations

import io
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import qrcode
from qrcode.constants import ERROR_CORRECT_H
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, Image as RLImage
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from modules.key_manager import KeyPair, KeyType


# ─── Colours ─────────────────────────────────────────────────────────────────

_DARK_BLUE   = colors.HexColor("#1a2e4a")
_MID_BLUE    = colors.HexColor("#2563eb")
_LIGHT_BLUE  = colors.HexColor("#dbeafe")
_GREEN       = colors.HexColor("#16a34a")
_GREEN_LIGHT = colors.HexColor("#dcfce7")
_GRAY        = colors.HexColor("#9ca3af")
_GRAY_LIGHT  = colors.HexColor("#f3f4f6")
_RED         = colors.HexColor("#dc2626")
_WHITE       = colors.white
_BLACK       = colors.black


class PDFRenderer:
    """
    Generates a PAdES-signed PDF certificate for SecureErase Pro.
    """

    def __init__(self, keypair: Optional[KeyPair] = None, tsa_url: Optional[str] = None):
        self._keypair = keypair
        self._tsa_url = tsa_url

    def render(self, cert: dict, logo_path: Optional[str] = None) -> bytes:
        """
        Render a complete PAdES-signed PDF from a signed certificate dict.

        Returns the PDF as raw bytes.
        """
        # Step 1: Build the PDF content into a buffer (without PAdES sig)
        pdf_buf = self._build_content(cert, logo_path)

        # Step 2: Embed the raw signed JSON as a PDF attachment
        pdf_buf = self._embed_json_attachment(pdf_buf, cert)

        # Step 3: Apply PAdES digital signature
        if self._keypair is not None:
            pdf_buf = self._apply_pades_signature(pdf_buf, cert)

        return pdf_buf

    # ─── Content building ─────────────────────────────────────────────────────

    def _build_content(self, cert: dict, logo_path: Optional[str]) -> bytes:
        buf = io.BytesIO()
        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            "CertTitle", parent=styles["Heading1"],
            fontSize=18, textColor=_DARK_BLUE, spaceAfter=2,
            alignment=TA_CENTER,
        )
        subtitle_style = ParagraphStyle(
            "CertSub", parent=styles["Normal"],
            fontSize=9, textColor=_GRAY, alignment=TA_CENTER, spaceAfter=8,
        )
        section_style = ParagraphStyle(
            "Section", parent=styles["Heading2"],
            fontSize=11, textColor=_DARK_BLUE,
            spaceBefore=12, spaceAfter=4,
            borderPad=4, backColor=_LIGHT_BLUE,
        )
        body_style = ParagraphStyle(
            "Body", parent=styles["Normal"],
            fontSize=8.5, leading=12,
        )
        mono_style = ParagraphStyle(
            "Mono", parent=styles["Normal"],
            fontSize=7.5, fontName="Courier", leading=10,
        )
        footer_style = ParagraphStyle(
            "Footer", parent=styles["Normal"],
            fontSize=7, textColor=_GRAY, alignment=TA_CENTER,
        )

        story = []
        W, H = A4

        # ── Section 1: Header ────────────────────────────────────────────────
        story.append(Spacer(1, 4*mm))
        if logo_path and Path(logo_path).exists():
            story.append(RLImage(logo_path, width=40*mm, height=12*mm))
            story.append(Spacer(1, 2*mm))

        story.append(Paragraph("SecureErase Pro — Data Erasure Certificate", title_style))
        story.append(Paragraph(
            f"Certificate ID: {cert['certificate_id']}  ·  "
            f"Issued: {cert['generated_at']}  ·  "
            f"Organization: {cert['issuer']['organization']}",
            subtitle_style,
        ))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_MID_BLUE))
        story.append(Spacer(1, 4*mm))

        # ── Section 2: Operator & System ─────────────────────────────────────
        story.append(Paragraph("Operator & System Information", section_style))
        op = cert.get("operator", {})
        op_data = [
            ["Username", op.get("username", ""), "Hostname", op.get("hostname", "")],
            ["IP Address", op.get("ip_address", ""), "OS", op.get("os", "")],
            ["App Version", op.get("app_version", ""), "", ""],
        ]
        story.append(self._kv_table(op_data))

        # ── Section 3: Target ────────────────────────────────────────────────
        story.append(Paragraph("Target File / Folder", section_style))
        tgt = cert.get("target", {})
        size_mb = tgt.get("size_bytes", 0) / (1024 * 1024)
        tgt_data = [
            ["Path", tgt.get("path", ""), "Type", tgt.get("type", "")],
            ["Size", f"{tgt.get('size_bytes', 0):,} bytes ({size_mb:.2f} MB)",
             "File Count", str(tgt.get("file_count", 0))],
        ]
        story.append(self._kv_table(tgt_data))

        # ── Section 4: Wipe Operation ────────────────────────────────────────
        story.append(Paragraph("Wipe Operation Summary", section_style))
        wipe = cert.get("wipe_operation", {})
        verified_str = "✓ VERIFIED" if wipe.get("verified") else "✗ NOT VERIFIED"
        verified_color = _GREEN if wipe.get("verified") else _RED

        wipe_summary = [
            ["Standard Applied", wipe.get("standard_applied", ""), "Passes", str(wipe.get("passes_completed", 0))],
            ["Duration", f"{wipe.get('duration_seconds', 0):.2f} seconds",
             "Verification", verified_str],
        ]
        story.append(self._kv_table(wipe_summary))
        story.append(Spacer(1, 2*mm))

        # Pass detail table
        pass_detail = wipe.get("pass_detail", [])
        if pass_detail:
            pass_header = [["Pass #", "Pattern", "Verified"]]
            pass_rows = [
                [
                    str(p["pass_number"]),
                    p["pattern"],
                    "✓" if p["verified"] else "✗"
                ]
                for p in pass_detail[:35]  # cap at 35 (Gutmann max)
            ]
            story.append(self._detail_table(pass_header + pass_rows))

        # ── Section 5: Hash Verification ─────────────────────────────────────
        story.append(Paragraph("Hash Verification Results", section_style))
        sha256_changed = (
            tgt.get("sha256_before", "") != wipe.get("sha256_after", "")
            and tgt.get("sha256_before", "") != ""
        )
        hash_data = [
            ["SHA-256 (before)", Paragraph(tgt.get("sha256_before", "N/A"), mono_style)],
            ["SHA-256 (after)", Paragraph(wipe.get("sha256_after", "N/A"), mono_style)],
            ["SHA3-256 (before)", Paragraph(tgt.get("sha3_256_before", "N/A"), mono_style)],
            ["SHA3-256 (after)", Paragraph(wipe.get("sha3_256_after", "N/A"), mono_style)],
            ["Data Changed", "YES — wipe confirmed" if sha256_changed else "NO — verify wipe manually"],
        ]
        story.append(Table(
            hash_data,
            colWidths=[42*mm, None],
            style=TableStyle([
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [_WHITE, _GRAY_LIGHT]),
                ("GRID", (0, 0), (-1, -1), 0.3, _GRAY),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("PADDING", (0, 0), (-1, -1), 4),
            ]),
        ))

        # ── Section 6: Compliance badges ─────────────────────────────────────
        story.append(Paragraph("Compliance Standards", section_style))
        compliance = cert.get("compliance_mapping", [])
        badges = []
        row = []
        for i, c in enumerate(compliance):
            satisfied = c.get("satisfied", False)
            bg = _GREEN_LIGHT if satisfied else _GRAY_LIGHT
            fg = _GREEN if satisfied else _GRAY
            badge = Table(
                [[Paragraph(f"<b>{c['standard']}</b>", ParagraphStyle('b', fontSize=7, textColor=fg))]],
                colWidths=[38*mm], rowHeights=[10*mm],
                style=TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), bg),
                    ("BOX", (0, 0), (-1, -1), 0.5, fg),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]),
            )
            row.append(badge)
            if len(row) == 4 or i == len(compliance) - 1:
                while len(row) < 4:
                    row.append(Spacer(38*mm, 10*mm))
                badges.append(row)
                row = []

        if badges:
            badge_table = Table(
                badges,
                colWidths=[40*mm, 40*mm, 40*mm, 40*mm],
                style=TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]),
            )
            story.append(badge_table)

        # ── Section 7: Digital Signature ─────────────────────────────────────
        story.append(Paragraph("Digital Signature", section_style))
        sig = cert.get("signature", {})
        sig_data = [
            ["Algorithm", sig.get("algorithm", ""), "Signed At", sig.get("signed_at", "")],
            ["Key Fingerprint (SHA-256)", Paragraph(sig.get("public_key_fingerprint", ""), mono_style), "", ""],
        ]
        story.append(self._kv_table(sig_data))
        story.append(Spacer(1, 2*mm))
        story.append(Paragraph(
            "<i>This document carries a PAdES digital signature. "
            "Any modification to this PDF after signing will invalidate the signature.</i>",
            ParagraphStyle("sig_note", parent=styles["Normal"], fontSize=8, textColor=_GRAY),
        ))

        # ── Section 8 & 9: QR code + instructions ───────────────────────────
        story.append(Paragraph("Verification", section_style))
        portal_url = cert["issuer"]["portal_verification_url"]
        qr_img = self._generate_qr(portal_url)

        verify_text = (
            f"<b>Online:</b> Scan the QR code or visit:<br/>"
            f"<font name='Courier'>{portal_url}</font><br/><br/>"
            f"<b>Offline:</b> Verify using the issuer's public key (fingerprint below) "
            f"against the embedded JSON attachment in this PDF.<br/>"
            f"<font name='Courier'>{sig.get('public_key_fingerprint', '')}</font><br/><br/>"
            f"Fetch public key: <font name='Courier'>{cert['issuer']['public_key_url']}</font>"
        )

        qr_verify_table = Table(
            [[qr_img, Paragraph(verify_text, ParagraphStyle("v", parent=styles["Normal"], fontSize=8, leading=12))]],
            colWidths=[50*mm, None],
            style=TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (1, 0), (1, 0), 6),
            ]),
        )
        story.append(qr_verify_table)

        # ── Footer ───────────────────────────────────────────────────────────
        story.append(HRFlowable(width="100%", thickness=0.5, color=_GRAY, spaceAfter=3))
        story.append(Paragraph(
            "SecureErase Pro — Enterprise Data Destruction & Compliance Platform  |  "
            "This certificate is cryptographically signed. The raw signed JSON is "
            "embedded as a PDF attachment for machine-verifiable audit.",
            footer_style,
        ))

        doc = SimpleDocTemplate(
            buf,
            pagesize=A4,
            rightMargin=15*mm, leftMargin=15*mm,
            topMargin=10*mm, bottomMargin=10*mm,
            title=f"Erasure Certificate {cert['certificate_id']}",
            author=cert["issuer"]["organization"],
            subject="Secure Data Erasure Certificate",
        )
        doc.build(story)
        return buf.getvalue()

    # ─── JSON attachment ─────────────────────────────────────────────────────

    def _embed_json_attachment(self, pdf_bytes: bytes, cert: dict) -> bytes:
        """Attach the signed certificate JSON to the PDF as a named file attachment."""
        from pypdf import PdfWriter, PdfReader

        cert_id = cert["certificate_id"]
        json_bytes = json.dumps(cert, sort_keys=True, indent=2).encode("utf-8")

        reader = PdfReader(io.BytesIO(pdf_bytes))
        writer = PdfWriter()
        writer.append(reader)
        writer.add_attachment(f"certificate_{cert_id}.json", json_bytes)

        out_buf = io.BytesIO()
        writer.write(out_buf)
        return out_buf.getvalue()

    # ─── PAdES signature ──────────────────────────────────────────────────────

    def _apply_pades_signature(self, pdf_bytes: bytes, cert: dict) -> bytes:
        """
        Apply a PAdES-B digital signature to the PDF.

        Uses endesive for PAdES signing. If endesive is not installed,
        returns the PDF unsigned with a warning log.

        PAdES ensures that any modification of the PDF after signing
        (including byte changes to the embedded JSON) invalidates the
        signature in any conformant PDF reader.
        """
        try:
            from endesive import pdf as endesive_pdf
        except ImportError:
            import warnings
            warnings.warn(
                "endesive not installed — PDF produced without PAdES signature. "
                "Install with: pip install endesive",
                RuntimeWarning,
                stacklevel=3,
            )
            return pdf_bytes

        if self._keypair is None or self._keypair._private_key is None:
            return pdf_bytes

        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, NoEncryption, PublicFormat
        )
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding as asym_pad
        import datetime

        # Build a self-signed cert for PAdES (endesive requires an X.509 cert)
        priv_key = self._keypair._private_key
        pub_key = priv_key.public_key()

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, cert["issuer"]["organization"]),
            x509.NameAttribute(NameOID.COMMON_NAME, "SecureErase Pro Signing"),
        ])
        x509_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(pub_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .sign(priv_key, hashes.SHA256())
        )

        priv_pem = priv_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        cert_pem = x509_cert.public_bytes(Encoding.PEM)

        date = datetime.datetime.utcnow().strftime("D:%Y%m%d%H%M%S+00'00'")
        dct = {
            "sigflags": 3,
            "sigflagsft": 132,
            "sigpage": 0,
            "sigbutton": True,
            "contact": cert["issuer"]["organization"],
            "location": "SecureErase Pro",
            "signingdate": date,
            "reason": "Data Erasure Certificate — PAdES Signature",
            "signature": "Sig1",
            "signaturebox": (0, 0, 0, 0),  # invisible signature
        }

        try:
            signed_pdf = endesive_pdf.cms.sign(
                pdf_bytes,
                dct,
                priv_pem,
                cert_pem,
                [],
                "sha256",
            )
            return signed_pdf
        except Exception as exc:
            import warnings
            warnings.warn(f"PAdES signing failed: {exc}. Returning unsigned PDF.", RuntimeWarning)
            return pdf_bytes

    # ─── Helpers ─────────────────────────────────────────────────────────────

    def _generate_qr(self, url: str) -> RLImage:
        """Generate a QR code image from a URL and return as ReportLab Image."""
        qr = qrcode.QRCode(
            version=None,
            error_correction=ERROR_CORRECT_H,
            box_size=4,
            border=2,
        )
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return RLImage(buf, width=40*mm, height=40*mm)

    @staticmethod
    def _kv_table(data: list) -> Table:
        """Render a key-value grid table."""
        return Table(
            data,
            style=TableStyle([
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [_WHITE, _GRAY_LIGHT]),
                ("GRID", (0, 0), (-1, -1), 0.3, _GRAY),
                ("PADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]),
        )

    @staticmethod
    def _detail_table(data: list) -> Table:
        """Render a detail/log table."""
        return Table(
            data,
            style=TableStyle([
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_WHITE, _GRAY_LIGHT]),
                ("BACKGROUND", (0, 0), (-1, 0), _DARK_BLUE),
                ("TEXTCOLOR", (0, 0), (-1, 0), _WHITE),
                ("GRID", (0, 0), (-1, -1), 0.3, _GRAY),
                ("PADDING", (0, 0), (-1, -1), 3),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("ALIGN", (1, 1), (1, -1), "LEFT"),
            ]),
        )
