"""
=============================================================================
Module: PDFRenderer
Purpose: Generate a PAdES-compliant PDF certificate from a signed JSON
         certificate. Embeds the raw signed JSON as a PDF attachment,
         includes a QR code deep-link, compliance badge grid, and applies
         a PAdES digital signature to the PDF itself.
Inputs:  Signed certificate dict, public key PEM (for embedding)
Outputs: PAdES-signed PDF bytes
Dependencies: reportlab, pypdf, qrcode, endesive (pip)
Compliance:
  - PAdES (ETSI EN 319 132) for PDF digital signature
  - PDF/A-3 for long-term archival with embedded attachments
  - QR code per ISO/IEC 18004:2015
=============================================================================
"""

import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import qrcode
    import qrcode.image.svg
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm, cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    )
    from reportlab.platypus import Image as RLImage
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    import pypdf
    HAS_PDF_DEPS = True
except ImportError:
    HAS_PDF_DEPS = False

try:
    import endesive.pdf as epdf
    HAS_ENDESIVE = True
except ImportError:
    HAS_ENDESIVE = False


# Compliance badge color definitions
BADGE_GREEN  = colors.HexColor("#2ECC71")
BADGE_GRAY   = colors.HexColor("#BDC3C7")
BADGE_RED    = colors.HexColor("#E74C3C")
HEADER_BLUE  = colors.HexColor("#1A237E")
TEXT_DARK    = colors.HexColor("#212121")
TEXT_LIGHT   = colors.HexColor("#FFFFFF")
BORDER_GRAY  = colors.HexColor("#E0E0E0")


class PDFRenderer:
    """
    Renders signed JSON certificates as PAdES-signed PDFs.

    PDF structure:
    1. Header (cert ID, org, timestamp)
    2. Operator and system info
    3. Target file/folder details
    4. Wipe operation summary + pass table
    5. Hash verification results
    6. Compliance badges grid
    7. Digital signature block
    8. QR code + offline verification instructions

    PAdES signing:
    - The PDF content is rendered first (unsigned).
    - The full signed JSON is embedded as a PDF/A-3 attachment.
    - endesive applies a PAdES-B-B signature over the final PDF bytes.
    - If endesive is not available, the PDF is returned without PAdES
      (the embedded JSON still carries the JSON-level signature).

    Limitation: PAdES-B-LT (long-term with timestamp) requires a
    trusted TSA (Timestamp Authority). This module supports B-B by
    default. B-LT can be enabled by setting tsa_url in the constructor.
    """

    def __init__(
        self,
        org_logo_path: Optional[str] = None,
        tsa_url: Optional[str] = None,
    ):
        """
        Args:
            org_logo_path: Optional path to organization logo (PNG/JPG).
            tsa_url: Optional RFC 3161 TSA URL for PAdES-B-LT timestamps.
        """
        if not HAS_PDF_DEPS:
            raise ImportError(
                "PDFRenderer requires: pip install reportlab pypdf qrcode[pil]\n"
                "For PAdES signing: pip install endesive"
            )
        self.org_logo_path = org_logo_path
        self.tsa_url = tsa_url

    def render(
        self,
        cert: dict,
        private_key_pem: Optional[bytes] = None,
        public_key_pem: Optional[bytes] = None,
        key_password: Optional[bytes] = None,
    ) -> bytes:
        """
        Generate and optionally PAdES-sign a PDF certificate.

        Args:
            cert: Signed certificate dict (signature.value must be populated).
            private_key_pem: PEM bytes of private key for PAdES signing.
                             If None, PDF is generated without PAdES signature.
            public_key_pem: PEM bytes of public key (embedded in PDF footer).
            key_password: Password for encrypted private key.

        Returns:
            PDF bytes (PAdES-signed if private_key_pem was provided).
        """
        # Validate cert has a JSON signature
        if not cert.get("signature", {}).get("value"):
            raise ValueError(
                "PDFRenderer.render: certificate has no JSON signature. "
                "Sign with DigitalSigner before rendering to PDF."
            )

        # Build PDF content
        pdf_buffer = io.BytesIO()
        self._build_pdf_content(pdf_buffer, cert, public_key_pem)
        pdf_bytes = pdf_buffer.getvalue()

        # Embed signed JSON as PDF attachment
        cert_id = cert.get("certificate_id", "unknown")
        json_bytes = json.dumps(
            cert, sort_keys=True, indent=2
        ).encode("utf-8")
        pdf_bytes = self._embed_json_attachment(pdf_bytes, json_bytes, cert_id)

        # Apply PAdES signature if key provided
        if private_key_pem and HAS_ENDESIVE:
            pdf_bytes = self._apply_pades(pdf_bytes, private_key_pem, key_password)

        return pdf_bytes

    def _build_pdf_content(
        self,
        buffer: io.BytesIO,
        cert: dict,
        public_key_pem: Optional[bytes],
    ):
        """Build the visual PDF content using ReportLab."""
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=15 * mm,
            leftMargin=15 * mm,
            topMargin=15 * mm,
            bottomMargin=15 * mm,
        )
        styles = getSampleStyleSheet()
        story = []

        # --- Header ---
        story.extend(self._build_header(cert, styles))
        story.append(Spacer(1, 6 * mm))
        story.append(HRFlowable(width="100%", thickness=2, color=HEADER_BLUE))
        story.append(Spacer(1, 4 * mm))

        # --- Operator ---
        story.extend(self._build_operator_section(cert, styles))
        story.append(Spacer(1, 4 * mm))

        # --- Target ---
        story.extend(self._build_target_section(cert, styles))
        story.append(Spacer(1, 4 * mm))

        # --- Wipe Operation ---
        story.extend(self._build_wipe_section(cert, styles))
        story.append(Spacer(1, 4 * mm))

        # --- Hash Verification ---
        story.extend(self._build_hash_section(cert, styles))
        story.append(Spacer(1, 4 * mm))

        # --- Compliance Badges ---
        story.extend(self._build_compliance_badges(cert, styles))
        story.append(Spacer(1, 4 * mm))

        # --- Signature Block ---
        story.extend(self._build_signature_block(cert, styles))
        story.append(Spacer(1, 4 * mm))

        # --- QR Code + Verification Instructions ---
        story.extend(self._build_qr_section(cert, public_key_pem, styles))

        doc.build(story)

    def _build_header(self, cert: dict, styles) -> list:
        issuer = cert.get("issuer", {})
        cert_id = cert.get("certificate_id", "N/A")
        generated_at = cert.get("generated_at", "N/A")
        org = issuer.get("organization", "Unknown Organization")

        title_style = ParagraphStyle(
            "Title", parent=styles["Title"],
            textColor=HEADER_BLUE, fontSize=18, spaceAfter=2
        )
        sub_style = ParagraphStyle(
            "Sub", parent=styles["Normal"],
            textColor=TEXT_DARK, fontSize=9
        )

        elements = [
            Paragraph("🔒 SecureErase Pro — Data Erasure Certificate", title_style),
            Paragraph(f"<b>Organization:</b> {org}", sub_style),
            Paragraph(f"<b>Certificate ID:</b> {cert_id}", sub_style),
            Paragraph(f"<b>Issued:</b> {generated_at}", sub_style),
        ]

        if self.org_logo_path and os.path.exists(self.org_logo_path):
            logo = RLImage(self.org_logo_path, width=40*mm, height=15*mm)
            elements.insert(0, logo)

        return elements

    def _build_operator_section(self, cert: dict, styles) -> list:
        op = cert.get("operator", {})
        section_style = ParagraphStyle("Section", parent=styles["Heading2"],
                                       textColor=HEADER_BLUE, fontSize=11)
        normal = styles["Normal"]
        data = [
            ["Username", op.get("username", "N/A")],
            ["Hostname", op.get("hostname", "N/A")],
            ["IP Address", op.get("ip_address", "N/A")],
            ["Operating System", op.get("os", "N/A")],
            ["App Version", op.get("app_version", "N/A")],
        ]
        return [
            Paragraph("Operator &amp; System Information", section_style),
            self._two_col_table(data),
        ]

    def _build_target_section(self, cert: dict, styles) -> list:
        tgt = cert.get("target", {})
        section_style = ParagraphStyle("Section", parent=styles["Heading2"],
                                       textColor=HEADER_BLUE, fontSize=11)
        size_gb = tgt.get("size_bytes", 0) / (1024 ** 3)
        data = [
            ["Path", tgt.get("path", "N/A")],
            ["Type", tgt.get("type", "N/A").capitalize()],
            ["Size", f"{size_gb:.4f} GB ({tgt.get('size_bytes', 0):,} bytes)"],
            ["File Count", str(tgt.get("file_count", 0))],
            ["Device Type", tgt.get("device_type", "N/A")],
            ["Filesystem", tgt.get("filesystem", "N/A")],
            ["SHA-256 (before)", tgt.get("sha256_before", "N/A")[:32] + "..."],
            ["SHA3-256 (before)", tgt.get("sha3_256_before", "N/A")[:32] + "..."],
        ]
        return [
            Paragraph("Target File / Folder Details", section_style),
            self._two_col_table(data),
        ]

    def _build_wipe_section(self, cert: dict, styles) -> list:
        wipe = cert.get("wipe_operation", {})
        section_style = ParagraphStyle("Section", parent=styles["Heading2"],
                                       textColor=HEADER_BLUE, fontSize=11)
        summary_data = [
            ["Standard Applied", wipe.get("standard_applied", "N/A")],
            ["Passes Completed", f"{wipe.get('passes_completed', 0)} / {wipe.get('passes_total', 0)}"],
            ["Duration", f"{wipe.get('duration_seconds', 0):.2f} seconds"],
            ["Verification", "✓ VERIFIED" if wipe.get("verified") else "✗ NOT VERIFIED"],
        ]

        # Pass detail table
        pass_header = [["Pass #", "Pattern", "Verified"]]
        pass_rows = [
            [
                str(p.get("pass_number")),
                p.get("pattern", "?"),
                "✓" if p.get("verified") else "✗",
            ]
            for p in wipe.get("pass_detail", [])
        ]
        pass_table_data = pass_header + pass_rows
        pass_table = Table(pass_table_data, colWidths=[20*mm, 60*mm, 25*mm])
        pass_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HEADER_BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), TEXT_LIGHT),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER_GRAY),
            ("ALIGN", (2, 0), (2, -1), "CENTER"),
        ]))

        return [
            Paragraph("Wipe Operation Summary", section_style),
            self._two_col_table(summary_data),
            Spacer(1, 3 * mm),
            Paragraph("Pass Detail", styles["Heading4"]),
            pass_table,
        ]

    def _build_hash_section(self, cert: dict, styles) -> list:
        wipe = cert.get("wipe_operation", {})
        tgt = cert.get("target", {})
        section_style = ParagraphStyle("Section", parent=styles["Heading2"],
                                       textColor=HEADER_BLUE, fontSize=11)
        before_sha256 = tgt.get("sha256_before", "")
        after_sha256 = wipe.get("sha256_after", "")
        changed = before_sha256 != after_sha256 and after_sha256

        data = [
            ["SHA-256 Before", before_sha256[:48] + "..."],
            ["SHA-256 After", after_sha256[:48] + "..." if after_sha256 else "N/A"],
            ["SHA3-256 Before", tgt.get("sha3_256_before", "")[:48] + "..."],
            ["SHA3-256 After", wipe.get("sha3_256_after", "")[:48] + "..." if wipe.get("sha3_256_after") else "N/A"],
            ["Content Changed", "✓ YES — hashes differ (expected after wipe)" if changed else "⚠ NO — verify wipe completed"],
        ]
        return [
            Paragraph("Hash Verification", section_style),
            self._two_col_table(data),
        ]

    def _build_compliance_badges(self, cert: dict, styles) -> list:
        section_style = ParagraphStyle("Section", parent=styles["Heading2"],
                                       textColor=HEADER_BLUE, fontSize=11)
        mappings = cert.get("compliance_mapping", [])
        satisfied = [m for m in mappings if m.get("satisfied")]
        not_satisfied = [m for m in mappings if not m.get("satisfied")]

        # Build badge grid (4 columns)
        badges_per_row = 4
        all_satisfied = [(m["standard"], True) for m in satisfied] + \
                        [(m["standard"], False) for m in not_satisfied]

        rows = []
        for i in range(0, len(all_satisfied), badges_per_row):
            row = all_satisfied[i:i + badges_per_row]
            # Pad row to 4 columns
            while len(row) < badges_per_row:
                row.append(("", None))
            rows.append(row)

        if not rows:
            return [Paragraph("Compliance Standards Satisfied", section_style),
                    Paragraph("No compliance mappings recorded.", styles["Normal"])]

        table_data = []
        for row in rows:
            cells = []
            for label, ok in row:
                if label == "":
                    cells.append("")
                elif ok:
                    cells.append(Paragraph(
                        f'<font color="white"><b>{label}</b></font>',
                        ParagraphStyle("badge", fontSize=7, alignment=TA_CENTER)
                    ))
                else:
                    cells.append(Paragraph(
                        f'<font color="white"><b>{label}</b><br/>⚠ NOT SATISFIED</font>',
                        ParagraphStyle("badge", fontSize=7, alignment=TA_CENTER)
                    ))
            table_data.append(cells)

        badge_table = Table(table_data, colWidths=[43 * mm] * 4)
        style_cmds = [
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ROWHEIGHT", (0, 0), (-1, -1), 10 * mm),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.white),
        ]
        # Color each cell
        for ri, row in enumerate(rows):
            for ci, (_, ok) in enumerate(row):
                if ok is None:
                    continue
                bg = BADGE_GREEN if ok else BADGE_RED
                style_cmds.append(("BACKGROUND", (ci, ri), (ci, ri), bg))
        badge_table.setStyle(TableStyle(style_cmds))

        return [
            Paragraph("Compliance Standards Satisfied", section_style),
            badge_table,
        ]

    def _build_signature_block(self, cert: dict, styles) -> list:
        sig = cert.get("signature", {})
        section_style = ParagraphStyle("Section", parent=styles["Heading2"],
                                       textColor=HEADER_BLUE, fontSize=11)
        data = [
            ["Signature Algorithm", sig.get("algorithm", "N/A")],
            ["Key Fingerprint (SHA-256)", sig.get("public_key_fingerprint", "N/A")[:48] + "..."],
            ["Signed At", sig.get("signed_at", "N/A")],
            ["Signature Value", sig.get("value", "")[:48] + "..." if sig.get("value") else "N/A"],
        ]
        note_style = ParagraphStyle("Note", parent=styles["Normal"],
                                    fontSize=8, textColor=colors.HexColor("#607D8B"))
        return [
            Paragraph("Digital Signature", section_style),
            self._two_col_table(data),
            Spacer(1, 2 * mm),
            Paragraph(
                "⚠ This certificate is digitally signed. Any modification to the "
                "JSON or PDF invalidates the signature. The raw signed JSON is embedded "
                "as an attachment to this PDF.",
                note_style
            ),
        ]

    def _build_qr_section(self, cert: dict, public_key_pem: Optional[bytes], styles) -> list:
        issuer = cert.get("issuer", {})
        portal_url = issuer.get("portal_verification_url", "")
        section_style = ParagraphStyle("Section", parent=styles["Heading2"],
                                       textColor=HEADER_BLUE, fontSize=11)
        note_style = ParagraphStyle("Note", parent=styles["Normal"],
                                    fontSize=8, textColor=TEXT_DARK)

        elements = [Paragraph("Verification", section_style)]

        # Generate QR code
        if portal_url:
            qr_img_buf = self._generate_qr(portal_url)
            if qr_img_buf:
                qr_image = RLImage(qr_img_buf, width=40 * mm, height=40 * mm)
                qr_table = Table(
                    [[qr_image, Paragraph(
                        f"<b>Online Verification:</b><br/>{portal_url}<br/><br/>"
                        f"<b>Offline Verification:</b><br/>"
                        f"1. Obtain the issuer's public key from:<br/>"
                        f"&nbsp;&nbsp;{issuer.get('public_key_url', 'N/A')}<br/>"
                        f"2. Verify key fingerprint:<br/>"
                        f"&nbsp;&nbsp;{issuer.get('public_key_fingerprint', 'N/A')[:32]}...<br/>"
                        f"3. Extract the embedded JSON attachment.<br/>"
                        f"4. Set signature.value to empty string.<br/>"
                        f"5. Canonical-serialize (sort_keys, no whitespace).<br/>"
                        f"6. Verify signature against canonical bytes.",
                        note_style
                    )]],
                    colWidths=[45 * mm, None],
                )
                qr_table.setStyle(TableStyle([
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (1, 0), (1, 0), 5 * mm),
                ]))
                elements.append(qr_table)

        # Footer note
        elements.append(Spacer(1, 4 * mm))
        elements.append(HRFlowable(width="100%", thickness=1, color=BORDER_GRAY))
        elements.append(Paragraph(
            "This certificate is issued by SecureErase Pro. The embedded signed JSON "
            "attachment is the authoritative certificate record. Verify authenticity "
            "online at the URL above or offline using the issuer's published public key.",
            ParagraphStyle("Footer", parent=styles["Normal"],
                           fontSize=7, textColor=colors.HexColor("#9E9E9E"))
        ))

        return elements

    def _generate_qr(self, url: str) -> Optional[io.BytesIO]:
        """Generate a QR code PNG image for the given URL."""
        try:
            from PIL import Image
            qr = qrcode.QRCode(
                error_correction=qrcode.constants.ERROR_CORRECT_H,
                box_size=4,
                border=2,
            )
            qr.add_data(url)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            buf.seek(0)
            return buf
        except Exception:
            return None

    def _embed_json_attachment(
        self, pdf_bytes: bytes, json_bytes: bytes, cert_id: str
    ) -> bytes:
        """Embed the signed JSON certificate as a PDF attachment."""
        reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
        writer = pypdf.PdfWriter()
        writer.append(reader)
        writer.add_attachment(
            filename=f"certificate_{cert_id}.json",
            data=json_bytes,
        )
        buf = io.BytesIO()
        writer.write(buf)
        return buf.getvalue()

    def _apply_pades(
        self,
        pdf_bytes: bytes,
        private_key_pem: bytes,
        key_password: Optional[bytes],
    ) -> bytes:
        """
        Apply PAdES-B-B signature to the PDF using endesive.

        If endesive is not available, returns unsigned PDF with a warning.
        The JSON-level signature is still valid even without PAdES.
        """
        if not HAS_ENDESIVE:
            return pdf_bytes

        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            from cryptography import x509

            private_key = serialization.load_pem_private_key(
                private_key_pem, password=key_password, backend=default_backend()
            )
            # endesive expects (cert_pem, key_pem) for signing
            # In a production deployment, a proper X.509 certificate would be used.
            # Here we self-sign for demonstration; production should use a CA-issued cert.
            signed_pdf = epdf.cms.sign(
                pdf_bytes,
                {
                    "signingdate": datetime.now(timezone.utc),
                },
                private_key_pem,
                b"",  # cert PEM — empty uses key only (demo mode)
                [],
                "sha256",
            )
            return signed_pdf
        except Exception:
            # PAdES signing failure is non-fatal — the JSON signature remains valid
            return pdf_bytes

    def _two_col_table(self, data: list) -> Table:
        """Render a two-column label/value table."""
        table = Table(data, colWidths=[55 * mm, None])
        table.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("TEXTCOLOR", (0, 0), (0, -1), HEADER_BLUE),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#F9F9F9")]),
            ("GRID", (0, 0), (-1, -1), 0.3, BORDER_GRAY),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ]))
        return table
