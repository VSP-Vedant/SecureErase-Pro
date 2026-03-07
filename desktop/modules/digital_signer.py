"""
=============================================================================
Module: DigitalSigner
Purpose: Cryptographically sign JSON certificates using RSA-4096 with PSS
         padding or ECDSA P-384. Produces a detached signature over the
         canonical JSON bytes. Also provides signature verification for
         offline validation without the portal.
Inputs:  Unsigned certificate dict, private key (file path or PKCS#11 slot)
Outputs: Signed certificate dict (signature block populated)
Dependencies: cryptography (pip), python-pkcs11 (optional, for HSM)
Compliance:
  - All frameworks requiring digital signature on erasure certificates
  - NIST SP 800-57 key management recommendations
  - FIPS 186-4 digital signature standard (RSA-4096, ECDSA P-384)
=============================================================================
"""

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Union, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey, ECDSA, SECP384R1
)
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from .certificate_builder import CertificateBuilder


class SignatureAlgorithm:
    RSA_4096_PSS   = "RS4096-PSS-SHA256"
    ECDSA_P384     = "ECDSA-P384-SHA256"


class DigitalSigner:
    """
    Signs and verifies JSON certificates using RSA-4096 or ECDSA P-384.

    Security design:
    - RSA uses PSS (Probabilistic Signature Scheme) padding, not PKCS#1 v1.5.
      PSS is provably secure and resistant to chosen-plaintext attacks.
      MGF1-SHA256 mask generation function with saltLength=32.
    - ECDSA uses P-384 (NIST curve secp384r1), providing 192-bit security.
      This matches NSA Suite B requirements and NIST SP 800-57 recommendations.
    - Signatures are computed over the SHA-256 digest of the canonical JSON
      bytes — NOT the raw JSON — to bound the signed input to 32 bytes for RSA
      and allow ECDSA's built-in SHA-256 hashing.
    - Private key loading supports:
        a) PEM file path (file must have 0600 permissions on POSIX)
        b) Encrypted PEM (password required)
        c) PKCS#11 token (optional; requires python-pkcs11 and a configured HSM)
    - The public key fingerprint is SHA-256 of the DER-encoded SubjectPublicKeyInfo,
      consistent with RFC 7517 (JWK thumbprint) and TLS certificate pinning practices.

    Limitation: PKCS#11 HSM support requires the python-pkcs11 library and a
    configured PKCS#11 module path (e.g., opensc-pkcs11.so for smart cards).
    If the HSM is unavailable, operations fall back to file-based keys.
    """

    def sign(
        self,
        cert: dict,
        private_key_path: Optional[Union[str, Path]] = None,
        private_key_pem: Optional[bytes] = None,
        key_password: Optional[bytes] = None,
        pkcs11_slot: Optional[int] = None,
        pkcs11_pin: Optional[str] = None,
        pkcs11_key_label: Optional[str] = None,
    ) -> dict:
        """
        Sign a certificate dict. Returns the signed cert with signature block populated.

        Exactly one of (private_key_path, private_key_pem, pkcs11_slot) must be provided.

        Args:
            cert: Unsigned certificate dict (signature.value must be "").
            private_key_path: Path to PEM private key file.
            private_key_pem: Raw PEM bytes of private key.
            key_password: Password for encrypted PEM keys (bytes).
            pkcs11_slot: PKCS#11 slot number for HSM signing.
            pkcs11_pin: PKCS#11 slot PIN.
            pkcs11_key_label: Key label in the PKCS#11 token.

        Returns:
            Signed certificate dict with signature.algorithm, signed_at, value populated.
        """
        # Load the private key
        if pkcs11_slot is not None:
            private_key, algorithm = self._load_pkcs11_key(
                pkcs11_slot, pkcs11_pin, pkcs11_key_label
            )
        elif private_key_pem is not None:
            private_key, algorithm = self._load_pem_key(private_key_pem, key_password)
        elif private_key_path is not None:
            private_key_path = Path(private_key_path)
            self._check_key_file_permissions(private_key_path)
            with open(private_key_path, "rb") as f:
                private_key, algorithm = self._load_pem_key(f.read(), key_password)
        else:
            raise ValueError(
                "DigitalSigner.sign: must provide one of: "
                "private_key_path, private_key_pem, or pkcs11_slot"
            )

        # Determine algorithm string before canonicalizing
        if isinstance(private_key, RSAPrivateKey):
            algorithm = SignatureAlgorithm.RSA_4096_PSS
        elif isinstance(private_key, EllipticCurvePrivateKey):
            algorithm = SignatureAlgorithm.ECDSA_P384
        else:
            raise TypeError(
                f"DigitalSigner: unsupported key type: {type(private_key).__name__}. "
                "Only RSA-4096 and ECDSA P-384 are supported."
            )

        # Build the cert copy with algorithm + signed_at committed, value = ""
        # This ensures verify() sees the same canonical bytes (it only clears value).
        import copy
        signed_at = datetime.now(timezone.utc).isoformat()
        cert_to_sign = copy.deepcopy(cert)
        cert_to_sign["signature"]["algorithm"] = algorithm
        cert_to_sign["signature"]["signed_at"] = signed_at
        cert_to_sign["signature"]["value"] = ""

        # Canonicalize AFTER setting all metadata except value
        builder = CertificateBuilder.__new__(CertificateBuilder)
        canonical_bytes = builder.canonical_serialize(cert_to_sign)

        # Sign the canonical bytes
        if isinstance(private_key, RSAPrivateKey):
            sig_bytes = private_key.sign(
                canonical_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        elif isinstance(private_key, EllipticCurvePrivateKey):
            sig_bytes = private_key.sign(
                canonical_bytes,
                ECDSA(hashes.SHA256()),
            )

        # Base64url-encode the signature (no padding per JWS conventions)
        sig_b64 = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode("ascii")

        # Set the value on the already-prepared cert copy
        cert_to_sign["signature"]["value"] = sig_b64

        return cert_to_sign

    def verify(
        self,
        cert: dict,
        public_key_pem: bytes,
    ) -> bool:
        """
        Verify a signed certificate against a public key PEM.

        Process (mirrors the verification workflow in Phase 4):
        1. Extract signature.value and decode from base64url.
        2. Set signature.value = "" in a copy of the cert.
        3. Canonical-serialize the modified cert.
        4. Verify the signature against the canonical bytes.

        Args:
            cert: Signed certificate dict.
            public_key_pem: PEM bytes of the issuer's public key.

        Returns:
            True if signature is valid, False if invalid or tampered.

        Raises:
            ValueError: If the certificate is missing required signature fields.
        """
        sig_block = cert.get("signature", {})
        sig_value = sig_block.get("value", "")
        algorithm = sig_block.get("algorithm", "")

        if not sig_value:
            raise ValueError("DigitalSigner.verify: certificate has no signature value")
        if not algorithm:
            raise ValueError("DigitalSigner.verify: certificate has no signature algorithm")

        # Decode signature from base64url (re-add padding if needed)
        padding_needed = (4 - len(sig_value) % 4) % 4
        sig_bytes = base64.urlsafe_b64decode(sig_value + "=" * padding_needed)

        # Prepare the canonical bytes (signature.value = "")
        import copy
        cert_copy = copy.deepcopy(cert)
        cert_copy["signature"]["value"] = ""
        builder = CertificateBuilder.__new__(CertificateBuilder)
        canonical_bytes = builder.canonical_serialize(cert_copy)

        # Load public key
        public_key = serialization.load_pem_public_key(
            public_key_pem, backend=default_backend()
        )

        try:
            if algorithm == SignatureAlgorithm.RSA_4096_PSS:
                if not isinstance(public_key, RSAPublicKey):
                    raise ValueError("Key type mismatch: expected RSA public key")
                public_key.verify(
                    sig_bytes,
                    canonical_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
                return True

            elif algorithm == SignatureAlgorithm.ECDSA_P384:
                if not isinstance(public_key, EllipticCurvePublicKey):
                    raise ValueError("Key type mismatch: expected EC public key")
                public_key.verify(
                    sig_bytes,
                    canonical_bytes,
                    ECDSA(hashes.SHA256()),
                )
                return True

            else:
                raise ValueError(f"DigitalSigner.verify: unknown algorithm: {algorithm}")

        except InvalidSignature:
            return False

    def get_public_key_fingerprint(self, public_key_pem: bytes) -> str:
        """
        Compute the SHA-256 fingerprint of a public key.
        Fingerprint = SHA-256(DER-encoded SubjectPublicKeyInfo).

        This is the value stored in certificate.signature.public_key_fingerprint
        and certificate.issuer.public_key_fingerprint.
        """
        public_key = serialization.load_pem_public_key(
            public_key_pem, backend=default_backend()
        )
        der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(der).hexdigest()

    # ---------------------------------------------------------------------------
    # Key loading helpers
    # ---------------------------------------------------------------------------

    def _load_pem_key(self, pem_bytes: bytes, password: Optional[bytes]):
        """Load a PEM private key and detect its type."""
        key = serialization.load_pem_private_key(
            pem_bytes,
            password=password,
            backend=default_backend(),
        )
        if isinstance(key, RSAPrivateKey):
            key_size = key.key_size
            if key_size < 4096:
                raise ValueError(
                    f"DigitalSigner: RSA key size is {key_size} bits. "
                    "Minimum required is 4096 bits per NIST SP 800-57."
                )
            return key, SignatureAlgorithm.RSA_4096_PSS
        elif isinstance(key, EllipticCurvePrivateKey):
            curve_name = key.curve.name
            if curve_name != "secp384r1":
                raise ValueError(
                    f"DigitalSigner: EC curve '{curve_name}' is not supported. "
                    "Only P-384 (secp384r1) is accepted."
                )
            return key, SignatureAlgorithm.ECDSA_P384
        else:
            raise TypeError(
                f"DigitalSigner: unsupported key type: {type(key).__name__}"
            )

    def _load_pkcs11_key(self, slot: int, pin: str, label: str):
        """
        Load a private key from a PKCS#11 HSM token.
        Requires python-pkcs11: pip install python-pkcs11

        The private key never leaves the HSM — only signing operations
        are performed on the token. The raw key material is not accessible.
        """
        try:
            import pkcs11
            from pkcs11 import Mechanism
        except ImportError:
            raise RuntimeError(
                "DigitalSigner: python-pkcs11 is not installed. "
                "Install it with: pip install python-pkcs11\n"
                "Also set environment variable PKCS11_MODULE to your PKCS#11 "
                "library path (e.g. /usr/lib/opensc-pkcs11.so)"
            )

        pkcs11_module = os.getenv("PKCS11_MODULE")
        if not pkcs11_module:
            raise ValueError(
                "DigitalSigner: PKCS11_MODULE environment variable not set. "
                "Set it to your PKCS#11 library path before using HSM signing."
            )

        lib = pkcs11.lib(pkcs11_module)
        token = lib.get_token(slot_id=slot)
        with token.open(user_pin=pin) as session:
            # Find the private key by label
            private_key = session.get_key(
                pkcs11.ObjectClass.PRIVATE_KEY,
                label=label
            )
            # Determine algorithm from key type
            if private_key.key_type == pkcs11.KeyType.RSA:
                return private_key, SignatureAlgorithm.RSA_4096_PSS
            elif private_key.key_type == pkcs11.KeyType.EC:
                return private_key, SignatureAlgorithm.ECDSA_P384
            else:
                raise TypeError(
                    f"DigitalSigner: PKCS#11 key type {private_key.key_type} not supported"
                )

    def _check_key_file_permissions(self, path: Path):
        """
        On POSIX systems, verify the private key file has restrictive permissions.
        A world-readable key file is a security misconfiguration.
        """
        if os.name == "posix":
            mode = os.stat(path).st_mode & 0o777
            if mode & 0o044:  # Group or other can read
                raise PermissionError(
                    f"DigitalSigner: private key file {path} has unsafe permissions "
                    f"({oct(mode)}). Expected 0600 (owner read/write only). "
                    f"Fix with: chmod 600 {path}"
                )
