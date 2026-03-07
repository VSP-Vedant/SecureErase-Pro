# SecureErase Pro

**Enterprise-grade secure data destruction with cryptographically signed, auditable certificates.**

SecureErase Pro is an open-source system consisting of two components:

- **Desktop Application** — cross-platform tool that performs multi-standard file/folder deletion and generates digitally signed erasure certificates
- **Verification Portal** — web application and REST API for public, enterprise, and admin-level certificate verification

---

## Architecture Summary

```
┌─────────────────────────────────────────────────────────┐
│  Desktop App (Python + PyQt6)                           │
│  FileScanner → SecureWipeEngine/SSDHandler →            │
│  HashVerifier → CertificateBuilder → DigitalSigner →    │
│  PDFRenderer → AuditLogger → RegistryClient             │
└─────────────────────┬───────────────────────────────────┘
                      │  POST /api/v1/registry/register
                      ▼
┌─────────────────────────────────────────────────────────┐
│  Verification Portal (FastAPI + PostgreSQL + React)     │
│  APIGateway → VerificationEngine ← RegistryService      │
│  FileUploadHandler / QRDecodeHandler / IDLookupHandler  │
│  AuthService (JWT/SSO) + RateLimiter (Redis)            │
└─────────────────────────────────────────────────────────┘
```

Both components are independently deployable. **Offline verification** is always available using only the issuer's public key — no portal connectivity required.

---

## Supported Deletion Standards

| Standard | Passes | Suitable For |
|---|---|---|
| NIST SP 800-88 Rev.1 — Clear | 1 | HDDs, magnetic media |
| NIST SP 800-88 Rev.1 — Purge | Hardware command | SSDs, NVMe (ATA Secure Erase / NVMe Format) |
| DoD 5220.22-M (3-pass) | 3 | HDDs |
| DoD 5220.22-M (7-pass) | 7 | HDDs, classified |
| Gutmann 35-pass | 35 | HDDs (maximum assurance) |
| Schneier 7-pass | 7 | HDDs |
| AFSSI-5020 | 3 | USAF — unclassified |
| AR 380-19 | 3 | US Army |
| NAVSO P-5239-26 | 3 | US Navy |
| HMG IS5 Baseline | 1 | UK government baseline |
| HMG IS5 Enhanced | 3 | UK government enhanced |
| Single-pass zero-write | 1 | Fast wipe (non-classified) |
| Cryptographic erasure | Key deletion | SSDs, NVMe, encrypted drives |

> **SSD Warning:** Software multi-pass overwrites do **not** satisfy NIST SP 800-88 Purge for SSDs due to wear-leveling. SecureErase Pro routes SSD/NVMe targets to `SSDHandler`, which issues hardware `ATA Secure Erase` or `NVMe Format --ses=2` commands. This is documented in every certificate.

---

## Compliance Frameworks

| Framework | Controls Satisfied |
|---|---|
| ISO/IEC 27001:2022 | Annex A.8.10 — Information deletion |
| NIST SP 800-53 Rev.5 | MP-6 — Media Sanitization |
| GDPR | Article 5(1)(e) storage limitation; Article 17 right to erasure |
| PCI-DSS v4.0 | Requirement 9.4.6 — Electronic media disposal |
| HIPAA | 45 CFR §164.310(d)(2)(i) — ePHI media disposal |
| SOC 2 | CC6.5 — Logical and physical asset disposal |
| CCPA | §1798.105 — Consumer deletion obligations |
| ISO/IEC 27040:2015 | §5.4 — Storage media sanitization |

---

## Quick Start — Verification Portal (3 commands)

```bash
# 1. Clone the repo
git clone https://github.com/VSP-Vedant/SecureErase-Pro.git
cd SecureErase-Pro

# 2. Configure environment
cp .env.example .env
# Edit .env: set POSTGRES_PASSWORD, REDIS_PASSWORD, SECRET_KEY,
#            JWT_SECRET, ADMIN_INITIAL_PASSWORD, PORTAL_DOMAIN

# 3. Deploy
docker compose -f infra/docker-compose.yml up -d
```

The portal will be available at `https://${PORTAL_DOMAIN}` after Nginx starts.

### Run Database Migrations

```bash
docker compose -f infra/docker-compose.yml exec portal-backend \
  python -m alembic upgrade head
```

### Verify Health

```bash
curl https://${PORTAL_DOMAIN}/api/v1/health
# → {"status": "ok", "version": "0.1.0"}
```

---

## TLS Certificate Setup

Place your TLS certificates in `infra/certs/`:

```
infra/certs/
├── fullchain.pem    # Full certificate chain
└── privkey.pem      # Private key (chmod 600)
```

**Let's Encrypt** instructions are in `infra/docker-compose.yml` (certbot service, commented out).

---

## Desktop App Installation

### Prerequisites

```bash
pip install -r desktop/requirements.txt
```

Requires Python 3.11+, `hdparm` (Linux) or `diskutil` (macOS) for SSD Purge.

### Run (development)

```bash
python desktop/main.py
```

### Generate Signing Keys

```python
from desktop.modules.key_manager import KeyManager, KeyType
km = KeyManager()
info = km.generate_keypair(KeyType.RSA_4096)
print("Fingerprint:", info.fingerprint)
print("Key saved to:", info.private_key_path)
```

### Package for Enterprise Deployment

```bash
# Windows MSI
pyinstaller desktop/main.py --onefile --windowed
# macOS PKG: use pyinstaller + pkgbuild
# Linux AppImage: use appimage-builder
```

---

## How to Verify a Certificate

### Online (Portal)

1. Visit `https://${PORTAL_DOMAIN}`
2. Upload the `.json` certificate file, enter the Certificate ID, or scan the QR code from the PDF
3. Public tier shows: validity, wipe standard, compliance frameworks
4. Enterprise tier (authenticated): full operator details, pass-by-pass log, audit chain

### Offline (No Internet Required)

```python
from desktop.modules.digital_signer import DigitalSigner
from desktop.modules.key_manager import KeyManager
import json

# Load the signed certificate
with open("certificate_abc123.json") as f:
    cert = json.load(f)

# Fetch issuer public key from cert's public_key_url (one-time, cache it)
# Or use a pre-distributed public key PEM
with open("issuer_public.pem", "rb") as f:
    pub_key_pem = f.read()

signer = DigitalSigner()
valid = signer.verify(cert=cert, public_key_pem=pub_key_pem)
print("Certificate valid:", valid)  # True = authentic and unmodified
```

---

## Development

### Run All Tests

```bash
# Install deps
pip install -r desktop/requirements.txt
pip install -r portal/backend/requirements.txt pytest pytest-cov

# Run (91 tests: 62 desktop + 29 portal)
python -m pytest
```

### Development Stack

```bash
docker compose -f infra/docker-compose.yml \
               -f infra/docker-compose.dev.yml up
```

Backend hot-reloads at `http://localhost:8000`, frontend at `http://localhost:3000`.

---

## Certificate Schema (Summary)

Every certificate includes:
- **UUID v4** — globally unique certificate ID
- **Pre/post wipe hashes** — SHA-256 + SHA3-256 of file content
- **Pass-by-pass detail** — pattern, verification result per pass
- **Compliance mapping** — which frameworks are satisfied and why
- **Audit chain** — HMAC-linked chain position (tamper-evident)
- **JWS signature** — RSA-4096-PSS or ECDSA-P384 over canonical JSON
- **Portal deep-link** — `https://${PORTAL_DOMAIN}/cert/{certificate_id}`

Full schema documented in [`docs/architecture/certificate-schema.md`](docs/architecture/certificate-schema.md).

---

## Enterprise SSO Integration

The verification portal supports:
- **OIDC** — configure `OIDC_DISCOVERY_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` in `.env`
- **SAML 2.0** — configure `SAML_IDP_METADATA_URL` in `.env`

Enterprise tier accounts are provisioned by an admin and linked to an SSO identity provider.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit with conventional commits: `feat(module): description`
4. Ensure all tests pass: `python -m pytest`
5. Open a pull request against `dev`

---

## License

**Apache License 2.0**

Chosen over MIT because:
- The patent grant clause protects users of SecureErase Pro from patent claims by contributors
- Attribution requirement ensures derivative enterprise builds credit the original
- Compatible with commercial use and enterprise redistribution
- Standard choice for security infrastructure tools (cf. HashiCorp Vault, OpenSSL)

See [`LICENSE`](LICENSE) for the full text.

---

## Security Disclosure

To report a security vulnerability, email `security@secureerase.local` (replace with your actual contact). Do **not** open a public GitHub issue for security bugs.

---

*SecureErase Pro v0.1.0 — Built to NIST SP 800-88 Rev.1, ISO/IEC 27001:2022, and GDPR standards.*
