"""
=============================================================================
Module: AuthService
Purpose: Tiered authentication: public (none), enterprise (JWT/API key),
         admin (JWT + MFA). Issues and validates JWT tokens, manages
         password hashing, TOTP MFA, and SSO claim validation.
Inputs:  Credentials, JWT tokens, API keys, OIDC/SAML claims
Outputs: User objects, JWT tokens, access tier strings
Dependencies: python-jose, bcrypt, pyotp, cryptography
Security:
  - bcrypt with cost factor 12 for password hashing
  - JWT signed with HS256 using SECRET_KEY from environment
  - TOTP (RFC 6238) for admin MFA — secrets stored AES-encrypted
  - API keys stored as SHA-256 hash only — raw key shown once
  - Admin endpoints require MFA even with valid JWT
=============================================================================
"""

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

import bcrypt
import pyotp
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from .crypto_utils import decrypt_column, encrypt_column, generate_api_key, hash_api_key
from .models import APIKey, User


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _get_secret() -> str:
    s = os.environ.get("JWT_SECRET", "")
    if not s or len(s) < 32:
        raise RuntimeError("JWT_SECRET must be at least 32 characters")
    return s


JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRY_MINUTES = int(os.environ.get("JWT_EXPIRY_MINUTES", "480"))  # 8h
ADMIN_TOKEN_EXPIRY_MINUTES = 60  # 1h for admin


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

def hash_password(plaintext: str) -> str:
    """bcrypt hash with cost factor 12."""
    return bcrypt.hashpw(plaintext.encode("utf-8"),
                          bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plaintext: str, hashed: str) -> bool:
    """Constant-time bcrypt comparison."""
    return bcrypt.checkpw(plaintext.encode("utf-8"), hashed.encode("utf-8"))


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------

def create_access_token(user_id: str, role: str, org_id: Optional[str] = None,
                         mfa_verified: bool = False) -> str:
    """Issue a signed JWT access token."""
    expiry_minutes = ADMIN_TOKEN_EXPIRY_MINUTES if role == "admin" else ACCESS_TOKEN_EXPIRY_MINUTES
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "role": role,
        "org_id": org_id,
        "mfa": mfa_verified,
        "iat": now,
        "exp": now + timedelta(minutes=expiry_minutes),
    }
    return jwt.encode(payload, _get_secret(), algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """
    Decode and validate a JWT token.
    Raises JWTError on invalid/expired tokens — callers must handle.
    """
    return jwt.decode(token, _get_secret(), algorithms=[JWT_ALGORITHM])


class AuthError(Exception):
    def __init__(self, message: str, status_code: int = 401):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

def login_with_password(email: str, password: str,
                         session: Session) -> tuple[User, str]:
    """
    Authenticate with email + password.
    Returns (user, access_token).
    For admin users, token has mfa=False — TOTP step required before admin access.
    """
    from sqlalchemy import select
    user = session.execute(
        select(User).where(User.email == email, User.active == True)
    ).scalar_one_or_none()

    if not user or not user.password_hash:
        raise AuthError("Invalid credentials")

    if not verify_password(password, user.password_hash):
        raise AuthError("Invalid credentials")

    token = create_access_token(
        str(user.id), user.role, user.org_id, mfa_verified=False
    )
    user.last_login_at = datetime.now(timezone.utc)
    session.flush()
    return user, token


def verify_totp(user: User, totp_code: str, session: Session) -> str:
    """
    Verify TOTP code and issue MFA-verified token for admin users.
    Returns new access_token with mfa=True.
    """
    if not user.mfa_enabled or not user.totp_secret_encrypted:
        raise AuthError("MFA not enrolled for this account", 400)

    try:
        totp_secret = decrypt_column(user.totp_secret_encrypted)
    except Exception:
        raise AuthError("MFA configuration error", 500)

    totp = pyotp.TOTP(totp_secret)
    # Allow ±1 window for clock skew
    if not totp.verify(totp_code, valid_window=1):
        raise AuthError("Invalid TOTP code")

    return create_access_token(str(user.id), user.role, user.org_id, mfa_verified=True)


def enroll_totp(user: User, session: Session) -> tuple[str, str]:
    """
    Generate TOTP secret for a user.
    Returns (totp_secret, otpauth_url) — secret shown once to user.
    Does NOT set mfa_enabled=True until verify_totp_enrollment() confirms it.
    """
    secret = pyotp.random_base32()
    user.totp_secret_encrypted = encrypt_column(secret)
    # Don't set mfa_enabled here — wait for confirmed enrollment
    session.flush()
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user.email, issuer_name="SecureErase Pro"
    )
    return secret, totp_uri


def confirm_totp_enrollment(user: User, totp_code: str, session: Session) -> None:
    """Confirm TOTP enrollment by verifying first code. Enables MFA."""
    if not user.totp_secret_encrypted:
        raise AuthError("TOTP not initialized — call enroll_totp first", 400)
    totp_secret = decrypt_column(user.totp_secret_encrypted)
    totp = pyotp.TOTP(totp_secret)
    if not totp.verify(totp_code, valid_window=1):
        raise AuthError("TOTP verification failed — check your authenticator app")
    user.mfa_enabled = True
    session.flush()


# ---------------------------------------------------------------------------
# API Key authentication
# ---------------------------------------------------------------------------

def authenticate_api_key(raw_key: str, session: Session) -> tuple[User, str]:
    """
    Authenticate via API key.
    Returns (user, tier) where tier is "enterprise" or "admin".
    """
    from sqlalchemy import select
    from datetime import datetime, timezone

    if not raw_key or not raw_key.startswith("sep_v1_"):
        raise AuthError("Invalid API key format")

    key_hash = hash_api_key(raw_key)
    api_key_row = session.execute(
        select(APIKey).where(
            APIKey.key_hash == key_hash,
            APIKey.revoked == False,
        )
    ).scalar_one_or_none()

    if not api_key_row:
        raise AuthError("Invalid or revoked API key")

    now = datetime.now(timezone.utc)
    if api_key_row.expires_at and api_key_row.expires_at < now:
        raise AuthError("API key has expired")

    # Update last used timestamp
    api_key_row.last_used_at = now
    session.flush()

    return api_key_row.tier


def create_api_key_for_user(label: str, org_id: Optional[str],
                              tier: str, created_by_user: User,
                              session: Session) -> tuple[str, APIKey]:
    """
    Create a new API key. Returns (raw_key, APIKey row).
    raw_key is shown once — never stored, only its hash is persisted.
    """
    raw_key, key_hash = generate_api_key()
    api_key_row = APIKey(
        key_hash=key_hash,
        key_prefix=raw_key[:8],
        label=label,
        org_id=org_id,
        tier=tier,
        created_by_user_id=created_by_user.id,
    )
    session.add(api_key_row)
    session.flush()
    return raw_key, api_key_row


# ---------------------------------------------------------------------------
# FastAPI dependency helpers
# ---------------------------------------------------------------------------

def get_tier_from_token(token: Optional[str]) -> str:
    """
    Determine access tier from JWT token.
    Returns "public" if no token, "enterprise" or "admin" based on role.
    Admin requires mfa=True in token.
    """
    if not token:
        return "public"
    try:
        payload = decode_access_token(token)
        role = payload.get("role", "enterprise")
        if role == "admin":
            if not payload.get("mfa", False):
                return "enterprise"  # admin without MFA gets enterprise tier
            return "admin"
        return "enterprise"
    except JWTError:
        return "public"


def require_admin(token: str) -> dict:
    """Raise AuthError if token does not represent an MFA-verified admin."""
    try:
        payload = decode_access_token(token)
    except JWTError as e:
        raise AuthError(f"Invalid token: {e}")
    if payload.get("role") != "admin":
        raise AuthError("Admin role required", 403)
    if not payload.get("mfa"):
        raise AuthError("MFA verification required for admin access", 403)
    return payload
