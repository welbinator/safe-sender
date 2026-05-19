# Sender Safety

An email filtering service that scans incoming SMTP traffic against per-customer rules and allows or blocks messages before delivery.

## Tech Stack

- **SMTP layer**: Python + aiosmtpd
- **API**: Python + FastAPI
- **Database**: PostgreSQL 16
- **Reverse proxy**: Nginx
- **Infrastructure**: Docker / Docker Compose
- **CI**: GitHub Actions

## Quick Start (local dev)

```bash
cp .env.example .env
# edit .env — set a real POSTGRES_PASSWORD
docker compose up -d
curl http://localhost/health   # → {"status": "ok"}
```

## Project

https://sendersafety.com
