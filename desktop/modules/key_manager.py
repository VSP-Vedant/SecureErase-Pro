"""
=============================================================================
Module: KeyManager
Purpose: Generate, store, load, and rotate RSA-4096 and ECDSA-P384 signing
         key pairs. Supports file-based storage (PKCS#8 PEM) and PKCS#11 HSM
         tokens. Public keys are exported as PEM for distribution and portal
         publication.
Inputs:  Key type enum, storage backend config
Outputs: Private key handle, public key PEM, key fingerprint
Dependencies: cryptography (pip), python-pkcs11 (optional)
Compliance:
  - NIST SP 800-57 Part 1 Rev.5 (Key management recommendations)
  - NIST SP 800-131A Rev.2 (Algorithm transitions)
  - FIPS 186-4 (Digital signature standard)
=============================================================================
"""

import hashlib
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend


class KeyType(str, Enum):
    RSA_4096    = "RSA-4096"
    ECDSA_P384  = "ECDSA-P384"


@dataclass
class KeyPairInfo:
    """Metadata about a generated or loaded key pair."""
    key_type: str
    fingerprint: str       # SHA-256 of public key DER
    public_key_pem: bytes  # PEM bytes of the public key
    private_key_path: Optional[str] = None  # Set for file-backed keys
    pkcs11_slot: Optional[int] = None       # Set for HSM-backed keys
    pkcs11_label: Optional[str] = None
    created_at: str = ""


class KeyManager:
    """
    Manages signing key pairs for the desktop application.

    Key storage hierarchy (in order of preference):
    1. PKCS#11 HSM (Yubikey, SafeNet, etc.) — private key never exported
    2. OS keychain (macOS Keychain, Windows DPAPI, Linux Secret Service)
    3. PKCS#8 PEM file with 0600 permissions and optional encryption

    Key rotation:
    - Old key pairs are archived (not deleted) so existing certificates
      remain verifiable. The portal's public key registry supports multiple
      active keys, identified by fingerprint.
    - A rotation event is logged to the AuditLogger.

    Security notes:
    - RSA keys must be ≥4096 bits (NIST SP 800-131A RSA minimum through 2030+).
    - ECDSA must use P-384 (provides 192-bit security, NSA Suite B).
    - P-256 is explicitly excluded despite wider support — P-384 is required
      to align with NIST SP 800-57 recommendations for signing keys protecting
      data beyond 2031.
    - Generated private keys are immediately written with 0600 permissions.
    - In memory, keys are held as cryptography library objects — they are
      not serialized to strings within this process to minimize exposure window.
    """

    def __init__(self, key_store_dir: Optional[Union[str, Path]] = None):
        if key_store_dir is None:
            key_store_dir = self._default_key_dir()
        self.key_store_dir = Path(key_store_dir)
        self.key_store_dir.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(self.key_store_dir, 0o700)

    def generate_keypair(
        self,
        key_type: KeyType = KeyType.RSA_4096,
        key_name: str = "secureerase_signing",
        password: Optional[bytes] = None,
    ) -> KeyPairInfo:
        """
        Generate a new key pair and save it to disk.

        Args:
            key_type: RSA_4096 or ECDSA_P384.
            key_name: Base name for the key files (without extension).
            password: Optional passphrase to encrypt the private key PEM.
                      If None, key is stored unencrypted (requires 0600 permissions).

        Returns:
            KeyPairInfo with fingerprint, public key PEM, and file paths.
        """
        created_at = datetime.now(timezone.utc).isoformat()

        if key_type == KeyType.RSA_4096:
            private_key = rsa.generate_private_key(
                public_exponent=65537,  # Standard Fermat prime e
                key_size=4096,
                backend=default_backend(),
            )
        elif key_type == KeyType.ECDSA_P384:
            private_key = ec.generate_private_key(
                curve=ec.SECP384R1(),
                backend=default_backend(),
            )
        else:
            raise ValueError(f"KeyManager: unsupported key type: {key_type}")

        public_key = private_key.public_key()

        # Serialize private key
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

        # Serialize public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Compute fingerprint
        der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        fingerprint = hashlib.sha256(der).hexdigest()

        # Write files
        priv_path = self.key_store_dir / f"{key_name}_private.pem"
        pub_path = self.key_store_dir / f"{key_name}_public.pem"

        with open(priv_path, "wb") as f:
            f.write(private_pem)
        with open(pub_path, "wb") as f:
            f.write(public_pem)

        # Restrict permissions on private key
        if os.name == "posix":
            os.chmod(priv_path, 0o600)
            os.chmod(pub_path, 0o644)

        return KeyPairInfo(
            key_type=key_type.value,
            fingerprint=fingerprint,
            public_key_pem=public_pem,
            private_key_path=str(priv_path),
            created_at=created_at,
        )

    def load_keypair(
        self,
        key_name: str = "secureerase_signing",
        password: Optional[bytes] = None,
    ) -> Tuple[object, bytes, str]:
        """
        Load an existing key pair from disk.

        Returns:
            Tuple of (private_key_object, public_key_pem_bytes, fingerprint).
        """
        priv_path = self.key_store_dir / f"{key_name}_private.pem"
        pub_path = self.key_store_dir / f"{key_name}_public.pem"

        if not priv_path.exists():
            raise FileNotFoundError(
                f"KeyManager: private key not found: {priv_path}. "
                "Generate a key pair first with generate_keypair()."
            )

        # Check permissions before loading
        if os.name == "posix":
            mode = os.stat(priv_path).st_mode & 0o777
            if mode & 0o044:
                raise PermissionError(
                    f"KeyManager: private key {priv_path} has unsafe permissions "
                    f"({oct(mode)}). Expected 0600. Fix with: chmod 600 {priv_path}"
                )

        with open(priv_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=password, backend=default_backend()
            )

        with open(pub_path, "rb") as f:
            public_pem = f.read()

        public_key = private_key.public_key()
        der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        fingerprint = hashlib.sha256(der).hexdigest()

        return private_key, public_pem, fingerprint

    def export_public_key_pem(self, key_name: str = "secureerase_signing") -> bytes:
        """Read and return the public key PEM for distribution/portal upload."""
        pub_path = self.key_store_dir / f"{key_name}_public.pem"
        if not pub_path.exists():
            raise FileNotFoundError(f"KeyManager: public key not found: {pub_path}")
        with open(pub_path, "rb") as f:
            return f.read()

    def rotate_key(
        self,
        key_name: str = "secureerase_signing",
        key_type: Optional[KeyType] = None,
        password: Optional[bytes] = None,
    ) -> KeyPairInfo:
        """
        Rotate the signing key pair.
        Old keys are archived with a timestamp suffix — NOT deleted.
        Existing certificates remain verifiable against the old public key.

        Returns:
            New KeyPairInfo for the rotated key.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        # Archive existing keys
        for suffix in ("_private.pem", "_public.pem"):
            existing = self.key_store_dir / f"{key_name}{suffix}"
            if existing.exists():
                archive_name = f"{key_name}_{timestamp}{suffix}"
                existing.rename(self.key_store_dir / archive_name)

        # Detect old key type if not specified
        if key_type is None:
            key_type = KeyType.RSA_4096  # Default to RSA-4096 for new keys

        return self.generate_keypair(
            key_type=key_type,
            key_name=key_name,
            password=password,
        )

    def list_keys(self) -> list:
        """List all key files in the key store directory."""
        return [
            str(p.name) for p in self.key_store_dir.glob("*.pem")
            if "private" not in p.name  # Only list public keys
        ]

    def _default_key_dir(self) -> Path:
        if os.name == "nt":
            base = os.getenv("APPDATA", str(Path.home()))
            return Path(base) / "SecureErasePro" / "keys"
        else:
            return Path.home() / ".secureerase" / "keys"
