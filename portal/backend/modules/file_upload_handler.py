"""
=============================================================================
Module: FileUploadHandler
Purpose: Accept, validate, and parse uploaded JSON certificate files.
         Enforces file size limits, MIME type checks, JSON schema
         validation, and routes to VerificationEngine.
Inputs:  Raw file bytes from multipart upload, max size config
Outputs: Parsed cert dict or validation error
Dependencies: json, pydantic
Security:
  - Reject files >1MB (configurable) to prevent DoS
  - Validate Content-Type before parsing
  - JSON schema checked against Phase 4 required fields via Pydantic
  - No file contents written to disk — parsed in memory only
=============================================================================
"""

import json
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic import UUID4


# ---------------------------------------------------------------------------
# Pydantic schema validation for uploaded certificates
# ---------------------------------------------------------------------------

class IssuerModel(BaseModel):
    organization: str = Field(min_length=1, max_length=256)
    portal_verification_url: str = Field(min_length=1)
    public_key_url: str = Field(min_length=1)
    public_key_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")


class OperatorModel(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    hostname: str = Field(min_length=1)
    ip_address: str = Field(min_length=1)
    os: str = Field(min_length=1)
    app_version: str = Field(min_length=1)


class TargetModel(BaseModel):
    path: str = Field(min_length=1)
    type: str = Field(pattern=r"^(file|folder)$")
    size_bytes: int = Field(ge=0)
    file_count: int = Field(ge=1)
    sha256_before: Optional[str] = Field(default=None,
                                          pattern=r"^[a-f0-9]{64}$")
    sha3_256_before: Optional[str] = Field(default=None,
                                            pattern=r"^[a-f0-9]{64}$")


class PassDetailModel(BaseModel):
    pass_number: int = Field(ge=1)
    pattern: str = Field(min_length=1)
    verified: bool


class WipeOperationModel(BaseModel):
    standard_applied: str = Field(min_length=1)
    passes_completed: int = Field(ge=1)
    pass_detail: list[PassDetailModel]
    duration_seconds: float = Field(gt=0)
    verified: bool
    sha256_after: Optional[str] = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    sha3_256_after: Optional[str] = Field(default=None, pattern=r"^[a-f0-9]{64}$")

    @field_validator("pass_detail")
    @classmethod
    def passes_match_count(cls, v, info):
        # passes_completed may differ from len(pass_detail) for interrupted wipes
        # so we just ensure the list is non-empty
        if not v:
            raise ValueError("pass_detail must contain at least one entry")
        return v


class ComplianceMappingModel(BaseModel):
    standard: str = Field(min_length=1)
    version: str
    control_reference: str
    satisfied: bool
    notes: Optional[str] = None


class RegistryModel(BaseModel):
    registered: bool
    registry_url: Optional[str] = None
    registered_at: Optional[str] = None


class AuditChainModel(BaseModel):
    previous_certificate_hash: Optional[str] = None
    chain_position: Optional[int] = Field(default=None, ge=1)


class SignatureModel(BaseModel):
    algorithm: str = Field(pattern=r"^(RS4096-PSS-SHA256|ECDSA-P384-SHA256)$")
    public_key_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    signed_at: str = Field(min_length=1)
    value: str = Field(min_length=1)


class CertificateSchema(BaseModel):
    certificate_id: UUID4
    schema_version: str = Field(pattern=r"^\d+\.\d+$")
    issuer: IssuerModel
    generated_at: str = Field(min_length=1)
    operator: OperatorModel
    target: TargetModel
    wipe_operation: WipeOperationModel
    compliance_mapping: list[ComplianceMappingModel]
    registry: RegistryModel
    audit_chain: AuditChainModel
    signature: SignatureModel

    @model_validator(mode="after")
    def fingerprints_match(self):
        """issuer.public_key_fingerprint must match signature.public_key_fingerprint"""
        if self.issuer.public_key_fingerprint != self.signature.public_key_fingerprint:
            raise ValueError(
                "issuer.public_key_fingerprint does not match signature.public_key_fingerprint"
            )
        return self


# ---------------------------------------------------------------------------
# Upload handler
# ---------------------------------------------------------------------------

MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB


class UploadValidationError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


def parse_and_validate_certificate(
    file_bytes: bytes,
    content_type: Optional[str] = None,
    max_size: int = MAX_FILE_SIZE,
) -> tuple[dict, CertificateSchema]:
    """
    Parse and validate an uploaded certificate JSON file.

    Args:
        file_bytes: Raw bytes from multipart upload
        content_type: MIME type from Content-Type header (optional check)
        max_size: Maximum allowed file size in bytes

    Returns:
        (raw_dict, validated_schema) tuple

    Raises:
        UploadValidationError with descriptive message on any failure
    """
    # Size check
    if len(file_bytes) > max_size:
        raise UploadValidationError(
            f"File too large: {len(file_bytes)} bytes (max {max_size} bytes)"
        )

    if len(file_bytes) == 0:
        raise UploadValidationError("Empty file uploaded")

    # MIME type hint check (not enforced strictly — MIME is client-controlled)
    if content_type and content_type not in (
        "application/json", "text/plain", "application/octet-stream"
    ):
        raise UploadValidationError(
            f"Unexpected content type: {content_type}. "
            f"Expected application/json"
        )

    # JSON parse
    try:
        raw_dict = json.loads(file_bytes.decode("utf-8"))
    except UnicodeDecodeError:
        raise UploadValidationError("File is not valid UTF-8 text")
    except json.JSONDecodeError as e:
        raise UploadValidationError(f"Invalid JSON: {e}")

    if not isinstance(raw_dict, dict):
        raise UploadValidationError("Certificate must be a JSON object, not an array or primitive")

    # Pydantic schema validation
    try:
        validated = CertificateSchema.model_validate(raw_dict)
    except Exception as e:
        # Extract first validation error message
        err_str = str(e)
        if len(err_str) > 512:
            err_str = err_str[:512] + "..."
        raise UploadValidationError(f"Schema validation failed: {err_str}")

    return raw_dict, validated
