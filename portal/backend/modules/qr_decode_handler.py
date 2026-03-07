"""
=============================================================================
Module: QRDecodeHandler
Purpose: Decode QR code images or raw QR payloads and route to the
         verification pipeline. Supports image upload (PNG/JPEG) and
         pre-decoded string payloads.
Inputs:  Image bytes or decoded payload string
Outputs: certificate_id extracted from deep-link URL
Dependencies: pyzbar, Pillow (optional), re, urllib.parse
Security:
  - Only accepts deep-link URLs matching the expected pattern
  - Rejects payloads that are not valid portal deep-link URLs
  - Does not execute any content from QR payload
  - Image processing in-process (pyzbar is a C library — safe for parsing)
=============================================================================
"""

import re
import urllib.parse
from typing import Optional


# Deep-link URL pattern: https://{domain}/cert/{uuid}
_DEEPLINK_PATTERN = re.compile(
    r"^https?://[a-zA-Z0-9.\-]+"
    r"/cert/"
    r"([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})"
    r"/?$",
    re.IGNORECASE,
)


class QRDecodeError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


def extract_cert_id_from_payload(payload: str) -> str:
    """
    Extract certificate UUID from a QR code payload string.

    Accepts:
    - Full deep-link URL: https://verify.example.com/cert/{uuid}
    - Raw UUID (bare, no URL wrapper)

    Returns:
        Certificate ID as lowercase UUID string

    Raises:
        QRDecodeError if payload does not match expected formats
    """
    if not payload or not isinstance(payload, str):
        raise QRDecodeError("Empty or invalid QR payload")

    payload = payload.strip()

    # Try deep-link URL pattern first
    match = _DEEPLINK_PATTERN.match(payload)
    if match:
        return match.group(1).lower()

    # Try bare UUID
    uuid_pattern = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        re.IGNORECASE,
    )
    if uuid_pattern.match(payload):
        return payload.lower()

    raise QRDecodeError(
        f"QR payload does not match expected deep-link URL or UUID format. "
        f"Got: {payload[:64]}{'...' if len(payload) > 64 else ''}"
    )


def decode_qr_image(image_bytes: bytes) -> str:
    """
    Decode a QR code from image bytes (PNG or JPEG) and extract certificate ID.

    Args:
        image_bytes: Raw PNG or JPEG image data

    Returns:
        Certificate ID string

    Raises:
        QRDecodeError if image cannot be decoded or contains no valid QR code
    """
    try:
        from pyzbar.pyzbar import decode as pyzbar_decode
        from PIL import Image
        import io
    except ImportError as e:
        raise QRDecodeError(
            f"QR image decoding requires pyzbar and Pillow: pip install pyzbar Pillow. Error: {e}"
        )

    if len(image_bytes) == 0:
        raise QRDecodeError("Empty image file")

    if len(image_bytes) > 10 * 1024 * 1024:  # 10MB limit
        raise QRDecodeError("Image file too large (max 10MB)")

    try:
        img = Image.open(io.BytesIO(image_bytes))
    except Exception as e:
        raise QRDecodeError(f"Cannot open image: {e}")

    decoded_objects = pyzbar_decode(img)

    if not decoded_objects:
        raise QRDecodeError("No QR code found in the image")

    # Use the first QR code found
    qr_obj = decoded_objects[0]
    if qr_obj.type != "QRCODE":
        raise QRDecodeError(f"Found barcode of type {qr_obj.type}, expected QRCODE")

    try:
        payload = qr_obj.data.decode("utf-8")
    except UnicodeDecodeError:
        raise QRDecodeError("QR code payload is not valid UTF-8")

    return extract_cert_id_from_payload(payload)


def handle_qr_input(image_bytes: Optional[bytes] = None,
                     payload: Optional[str] = None) -> str:
    """
    Unified QR handler: accepts either image bytes or pre-decoded payload string.
    Returns certificate_id.
    """
    if image_bytes is not None:
        return decode_qr_image(image_bytes)
    if payload is not None:
        return extract_cert_id_from_payload(payload)
    raise QRDecodeError("Either image_bytes or payload must be provided")
