"""
=============================================================================
Module: APIGateway
Purpose: FastAPI application — all REST endpoints for the verification
         portal. Implements three verification methods, certificate
         registration, public key management, admin operations, and auth.
Inputs:  HTTP requests (JSON body, multipart/form-data, path params)
Outputs: JSON responses with tier-appropriate certificate data
Dependencies: fastapi, sqlalchemy, modules/*
Security:
  - Rate limiting applied per zone before any DB access
  - Tier determined from Bearer JWT or API key — never from request body
  - Input validation via Pydantic before any service call
  - All errors return generic messages — no internal details to public
=============================================================================
"""

import hashlib
import json
import os
import uuid
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import (
    Depends, FastAPI, File, Form, Header, HTTPException,
    Request, UploadFile, status
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .models import Base
from .auth_service import (
    AuthError,
    authenticate_api_key,
    confirm_totp_enrollment,
    create_api_key_for_user,
    enroll_totp,
    get_tier_from_token,
    login_with_password,
    require_admin,
    verify_totp,
)
from .audit_log_service import (
    get_flagged_events,
    get_verification_stats,
    log_verification_event,
)
from .crypto_utils import hash_ip
from .file_upload_handler import UploadValidationError, parse_and_validate_certificate
from .id_lookup_handler import LookupError, lookup_and_verify
from .notification_service import send_anomaly_alert
from .qr_decode_handler import QRDecodeError, handle_qr_input
from .rate_limiter import check_rate_limit, get_rate_limit_headers
from .registry_service import (
    CertificateNotFound,
    RevocationError,
    get_public_key_pem,
    list_certificates,
    register_certificate,
    register_public_key,
    rotate_public_key,
    revoke_certificate,
)
from .verification_engine import (
    VerificationStatus,
    verify_certificate_bytes,
)


# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------

def get_engine():
    db_url = os.environ.get("DATABASE_URL", "")
    if not db_url:
        raise RuntimeError("DATABASE_URL is not set")
    return create_engine(db_url.replace("postgres://", "postgresql://", 1),
                          pool_pre_ping=True, pool_size=10, max_overflow=20)


_engine = None
_SessionLocal = None


def get_db() -> Session:
    global _engine, _SessionLocal
    if _engine is None:
        _engine = get_engine()
        _SessionLocal = sessionmaker(bind=_engine, autocommit=False, autoflush=False)
    db = _SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# ---------------------------------------------------------------------------
# App lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    # On startup: ensure tables exist (migrations should have run first)
    global _engine
    if _engine is None:
        _engine = get_engine()
    yield


app = FastAPI(
    title="SecureErase Pro — Verification Portal API",
    version="0.1.0",
    description="Certificate verification API for SecureErase Pro erasure certificates.",
    lifespan=lifespan,
    # Disable automatic OpenAPI UI on production (can be re-enabled per config)
    docs_url="/api/docs" if os.environ.get("LOG_LEVEL", "info") == "debug" else None,
    redoc_url=None,
)

# CORS
cors_origins = os.environ.get("CORS_ORIGINS", "").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in cors_origins if o.strip()],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def get_bearer_token(authorization: Optional[str] = Header(default=None)) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def resolve_tier(
    token: Optional[str] = Depends(get_bearer_token),
    x_api_key: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
) -> str:
    """Determine access tier from JWT or API key."""
    if x_api_key:
        try:
            return authenticate_api_key(x_api_key, db)
        except AuthError:
            return "public"
    return get_tier_from_token(token)


def rate_limit_middleware(request: Request, zone: str, db: Session, tier: str) -> None:
    """Apply rate limiting and add headers. Raises HTTP 429 if exceeded."""
    client_ip = request.client.host if request.client else "unknown"
    # Enterprise tier: org-level limiting (extract from token if available)
    org_id = None  # could be extracted from JWT claims if needed
    allowed, retry_after = check_rate_limit(client_ip, zone, org_id)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(retry_after)},
        )


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Public key endpoint (unauthenticated — required for offline verification)
# ---------------------------------------------------------------------------

@app.get("/api/v1/keys/{fingerprint}")
def get_public_key(fingerprint: str, db: Session = Depends(get_db)):
    """Retrieve issuer public key PEM by fingerprint (SHA-256 hex, 64 chars)."""
    if len(fingerprint) != 64 or not all(c in "0123456789abcdef" for c in fingerprint.lower()):
        raise HTTPException(400, "Invalid fingerprint format")
    pem = get_public_key_pem(fingerprint.lower(), db)
    if not pem:
        raise HTTPException(404, "Public key not found")
    return {"fingerprint": fingerprint, "pem": pem}


# ---------------------------------------------------------------------------
# Verification — Method 1: File Upload
# ---------------------------------------------------------------------------

@app.post("/api/v1/verify/upload")
async def verify_by_upload(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    tier: str = Depends(resolve_tier),
):
    """
    Verify a certificate by uploading the JSON file.
    Rate zone: public_verify (10/min for unauthenticated).
    """
    zone = "enterprise" if tier in ("enterprise", "admin") else "public_verify"
    rate_limit_middleware(request, zone, db, tier)

    client_ip = request.client.host if request.client else "unknown"
    cert_id = None
    result_status = "error"

    try:
        file_bytes = await file.read()
        raw_dict, validated = parse_and_validate_certificate(
            file_bytes,
            content_type=file.content_type,
        )
        cert_id = str(validated.certificate_id)

        # Fetch public key from registry (or fallback: embedded in cert)
        fp = raw_dict["issuer"]["public_key_fingerprint"]
        public_key_pem = get_public_key_pem(fp, db)
        if not public_key_pem:
            # Fallback: attempt using the key URL from cert (offline scenario)
            return JSONResponse(status_code=200, content={
                "status": "unregistered",
                "message": (
                    "Public key not found in this portal's registry. "
                    "This certificate may have been issued by a different portal instance. "
                    "Download the issuer's public key from "
                    f"{raw_dict['issuer'].get('public_key_url', 'the issuer portal')} "
                    "and verify offline."
                ),
                "certificate_id": cert_id,
            })

        result = verify_certificate_bytes(file_bytes, public_key_pem)
        result_status = result.status.value

        response_data = {
            "status": result.status.value,
            "message": result.message,
            "certificate_id": cert_id,
        }
        if result.algorithm:
            response_data["algorithm"] = result.algorithm
        if result.tamper_details and tier in ("enterprise", "admin"):
            response_data["tamper_details"] = result.tamper_details
        if tier == "public":
            response_data["certificate"] = result.public_data
        else:
            response_data["certificate"] = raw_dict  # full cert for enterprise

        return response_data

    except UploadValidationError as e:
        result_status = "invalid"
        raise HTTPException(422, e.message)
    except Exception as e:
        result_status = "error"
        raise HTTPException(500, "Verification processing error")
    finally:
        log_verification_event(
            method="file_upload",
            result=result_status,
            session=db,
            certificate_id=cert_id,
            ip_address=client_ip,
            tier=tier,
        )


# ---------------------------------------------------------------------------
# Verification — Method 2: Certificate ID Lookup
# ---------------------------------------------------------------------------

@app.get("/api/v1/verify/{cert_id}")
def verify_by_id(
    cert_id: str,
    request: Request,
    db: Session = Depends(get_db),
    tier: str = Depends(resolve_tier),
):
    """
    Verify a certificate by its UUID. Also accessible via deep-link.
    Rate zone: public_verify (10/min for unauthenticated).
    """
    zone = "enterprise" if tier in ("enterprise", "admin") else "public_verify"
    rate_limit_middleware(request, zone, db, tier)

    client_ip = request.client.host if request.client else "unknown"
    result_status = "error"

    try:
        response = lookup_and_verify(cert_id, db, tier)
        result_status = response.get("status", "error")
        return response
    except LookupError as e:
        result_status = "invalid"
        raise HTTPException(e.status_code, e.message)
    except Exception:
        result_status = "error"
        raise HTTPException(500, "Lookup error")
    finally:
        log_verification_event(
            method="id_lookup",
            result=result_status,
            session=db,
            certificate_id=cert_id,
            ip_address=client_ip,
            tier=tier,
        )


# ---------------------------------------------------------------------------
# Verification — Method 3: QR Code
# ---------------------------------------------------------------------------

class QRPayloadRequest(BaseModel):
    payload: Optional[str] = Field(default=None, max_length=2048,
                                    description="Pre-decoded QR string payload")


@app.post("/api/v1/verify/qr")
async def verify_by_qr(
    request: Request,
    qr_image: Optional[UploadFile] = File(default=None),
    payload: Optional[str] = Form(default=None),
    db: Session = Depends(get_db),
    tier: str = Depends(resolve_tier),
):
    """
    Verify a certificate via QR code (image upload or decoded payload).
    Routes to ID lookup after extracting certificate ID.
    """
    zone = "enterprise" if tier in ("enterprise", "admin") else "public_verify"
    rate_limit_middleware(request, zone, db, tier)

    client_ip = request.client.host if request.client else "unknown"

    try:
        if qr_image:
            image_bytes = await qr_image.read()
            cert_id = handle_qr_input(image_bytes=image_bytes)
        elif payload:
            cert_id = handle_qr_input(payload=payload)
        else:
            raise HTTPException(400, "Provide either a QR image file or a decoded payload string")

    except QRDecodeError as e:
        raise HTTPException(422, e.message)

    # Route to ID lookup
    result_status = "error"
    try:
        response = lookup_and_verify(cert_id, db, tier)
        result_status = response.get("status", "error")
        response["qr_decoded_cert_id"] = cert_id
        return response
    except LookupError as e:
        result_status = "invalid"
        raise HTTPException(e.status_code, e.message)
    finally:
        log_verification_event(
            method="qr_scan",
            result=result_status,
            session=db,
            certificate_id=cert_id,
            ip_address=client_ip,
            tier=tier,
        )


# ---------------------------------------------------------------------------
# Certificate Registration (desktop app → portal)
# ---------------------------------------------------------------------------

@app.post("/api/v1/registry/register", status_code=201)
def register_cert(
    request: Request,
    cert_data: dict,
    db: Session = Depends(get_db),
    tier: str = Depends(resolve_tier),
    x_api_key: Optional[str] = Header(default=None),
):
    """
    Register a certificate from the desktop app.
    Requires enterprise or admin API key.
    """
    if tier not in ("enterprise", "admin"):
        raise HTTPException(403, "Certificate registration requires authentication")

    rate_limit_middleware(request, "enterprise", db, tier)

    try:
        cert_row = register_certificate(cert_data, db)
        return {
            "registered": True,
            "certificate_id": str(cert_row.id),
            "registered_at": cert_row.registered_at.isoformat(),
            "registry_url": cert_row.portal_verification_url,
        }
    except Exception as e:
        raise HTTPException(422, f"Registration failed: {e}")


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=8, max_length=128)


class TOTPRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8, pattern=r"^\d+$")


@app.post("/api/v1/auth/login")
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Login with email + password. Returns access token."""
    rate_limit_middleware(request, "auth", db, "public")
    try:
        user, token = login_with_password(req.email, req.password, db)
        return {
            "access_token": token,
            "token_type": "bearer",
            "role": user.role,
            "mfa_required": user.mfa_enabled and user.role == "admin",
        }
    except AuthError as e:
        raise HTTPException(e.status_code, e.message)


@app.post("/api/v1/auth/totp/verify")
def verify_mfa(
    req: TOTPRequest,
    request: Request,
    token: Optional[str] = Depends(get_bearer_token),
    db: Session = Depends(get_db),
):
    """Verify TOTP code after login. Returns MFA-upgraded token."""
    rate_limit_middleware(request, "auth", db, "public")
    if not token:
        raise HTTPException(401, "Access token required")
    try:
        from jose import jwt as jose_jwt, JWTError
        import os
        payload = jose_jwt.decode(token, os.environ.get("JWT_SECRET", ""),
                                   algorithms=["HS256"])
        user_id = payload.get("sub")
        from sqlalchemy import select
        from .models import User
        user = db.get(User, uuid.UUID(user_id))
        if not user:
            raise HTTPException(401, "User not found")
        new_token = verify_totp(user, req.code, db)
        return {"access_token": new_token, "token_type": "bearer"}
    except AuthError as e:
        raise HTTPException(e.status_code, e.message)


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------

@app.get("/api/v1/admin/certificates")
def admin_list_certs(
    page: int = 1,
    page_size: int = 50,
    token: Optional[str] = Depends(get_bearer_token),
    db: Session = Depends(get_db),
):
    require_admin(token or "")
    return list_certificates(db, page=page, page_size=page_size)


@app.delete("/api/v1/admin/certificates/{cert_id}")
def admin_revoke_cert(
    cert_id: str,
    reason_body: dict,
    token: Optional[str] = Depends(get_bearer_token),
    db: Session = Depends(get_db),
):
    payload = require_admin(token or "")
    reason = reason_body.get("reason", "")
    user_id = uuid.UUID(payload["sub"])
    try:
        revoke_certificate(uuid.UUID(cert_id), reason, user_id, db)
        return {"revoked": True, "certificate_id": cert_id}
    except (CertificateNotFound, RevocationError) as e:
        raise HTTPException(400, str(e))


@app.post("/api/v1/admin/keys")
def admin_register_key(
    key_data: dict,
    token: Optional[str] = Depends(get_bearer_token),
    db: Session = Depends(get_db),
):
    require_admin(token or "")
    try:
        pk = register_public_key(
            fingerprint=key_data["fingerprint"],
            pem=key_data["pem"],
            issuer_org=key_data.get("issuer_org", ""),
            algorithm=key_data.get("algorithm", "RS4096-PSS-SHA256"),
            session=db,
        )
        return {"fingerprint": pk.fingerprint, "active": pk.active}
    except Exception as e:
        raise HTTPException(422, str(e))


@app.post("/api/v1/admin/keys/{fingerprint}/rotate")
def admin_rotate_key(
    fingerprint: str,
    new_key_data: dict,
    token: Optional[str] = Depends(get_bearer_token),
    db: Session = Depends(get_db),
):
    require_admin(token or "")
    try:
        new_pk = rotate_public_key(
            old_fingerprint=fingerprint,
            new_pem=new_key_data["pem"],
            new_fingerprint=new_key_data["fingerprint"],
            new_algorithm=new_key_data.get("algorithm", "RS4096-PSS-SHA256"),
            issuer_org=new_key_data.get("issuer_org", ""),
            session=db,
        )
        return {"rotated": True, "new_fingerprint": new_pk.fingerprint}
    except Exception as e:
        raise HTTPException(422, str(e))


@app.get("/api/v1/admin/stats")
def admin_stats(
    days: int = 30,
    token: Optional[str] = Depends(get_bearer_token),
    db: Session = Depends(get_db),
):
    require_admin(token or "")
    return get_verification_stats(db, days=days)


@app.get("/api/v1/admin/flagged")
def admin_flagged_events(
    limit: int = 100,
    token: Optional[str] = Depends(get_bearer_token),
    db: Session = Depends(get_db),
):
    require_admin(token or "")
    return {"flagged_events": get_flagged_events(db, limit=limit)}
