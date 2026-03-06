# SecureErase Pro

Enterprise-grade secure data destruction platform with digitally signed, auditable erasure certificates.

> Full README will be committed at v0.1.0 release (Phase 9).

## Repository Structure

```
desktop/     — Cross-platform desktop erasure application (Python + PyQt6)
portal/      — Online verification portal (FastAPI + PostgreSQL + React)
infra/       — Docker Compose, Nginx, deployment configs
docs/        — Architecture, compliance, and deployment documentation
```

## Quick Start (Development)

```bash
cp .env.example .env   # fill all required values
docker compose -f infra/docker-compose.dev.yml up
```

## License

Apache 2.0
