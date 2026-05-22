# Deploy Runbook — Sender Safety

> Audit reference: **F-55** (Senior Dev Code Audit — 2026-05-22).
>
> Authoritative procedure for shipping `main` to production at
> `root@5.78.219.242:/opt/safe-sender`. If a step here is wrong, fix the runbook in the same PR — don't leave drift between code and docs.

---

## 1. Pre-flight

1. CI on `main` is green (backend pytest + frontend vitest + `npm audit --omit=dev --audit-level=high`).
2. Local `git log origin/main` matches the commit you intend to deploy.
3. Recent DB backup exists: `ssh root@5.78.219.242 'ls -lt /root/backups/ | head -5'`. If older than 24h, take one (step 2).

## 2. Backup (always — even for FE-only deploys)

```
ssh -i ~/.ssh/parchment-hetzner root@5.78.219.242 \
  "docker exec safe-sender-postgres-1 pg_dump -U sendersafety sendersafety \
   | gzip > /root/backups/pre-deploy-$(date +%Y%m%d-%H%M%S).sql.gz"
```

Verify size > 5 KB.

## 3. Pull and build

```
ssh -i ~/.ssh/parchment-hetzner root@5.78.219.242 'bash -s' <<'EOF'
set -euo pipefail
cd /opt/safe-sender
git fetch --all --prune
git reset --hard origin/main
docker compose build backend smtp nginx
EOF
```

Note: `restart` keeps the old image — you MUST `stop && rm && up -d` for any service whose image was rebuilt (see §4).

## 4. Rolling restart (per service)

> Foreground `docker compose up -d` hangs over SSH. Run as a **background** terminal session and poll, or use `nohup ... &` and disown.

```
# Backend (FastAPI)
docker compose stop backend && docker compose rm -f backend && docker compose up -d backend
# SMTP gateway
docker compose stop smtp    && docker compose rm -f smtp    && docker compose up -d smtp
# Nginx (multi-stage build bakes dashboard/dist)
docker compose stop nginx   && docker compose rm -f nginx   && docker compose up -d nginx
```

## 5. DB migrations (if alembic dir changed)

Migrations run automatically via `entrypoint.py` on backend start. Confirm:

```
docker logs --tail 80 safe-sender-backend-1 | grep -E 'alembic|migrat'
```

For a manual run: `docker exec safe-sender-backend-1 alembic upgrade head`.

## 6. Smoke tests

```
curl -fsS https://app.sendersafety.com/api/health        # {"status":"ok","db":"ok",...}
curl -fsS https://app.sendersafety.com/                  # HTTP 200, returns index.html
curl -fsS --resolve smtp.sendersafety.com:25:5.78.219.242 \
     -X POST telnet://smtp.sendersafety.com:25 || true   # banner check (use swaks if installed)
```

Inside the host:

```
docker exec safe-sender-backend-1 curl -fsS http://localhost:8000/metrics | head -5
docker exec safe-sender-smtp-1   curl -fsS http://localhost:9100/health
```

## 7. Rollback

```
ssh root@5.78.219.242 'bash -s' <<'EOF'
cd /opt/safe-sender
git reset --hard <previous-commit>
docker compose build backend smtp nginx
for s in backend smtp nginx; do
  docker compose stop $s && docker compose rm -f $s && docker compose up -d $s
done
EOF
```

If the bad deploy ran migrations, restore the backup BEFORE starting the old image:

```
gunzip -c /root/backups/pre-deploy-<ts>.sql.gz | \
  docker exec -i safe-sender-postgres-1 psql -U sendersafety sendersafety
```

## 8. Post-deploy

* Mark the deploy in Parchment (`safe-sender / deploys`).
* If an alert fired during the deploy window, attach the log excerpt to the deploy note.

---

### Container reference

| Service  | Container name              | Port (host) |
|----------|-----------------------------|-------------|
| backend  | `safe-sender-backend-1`     | 8000 (internal) |
| smtp     | `safe-sender-smtp-1`        | 25, 587 |
| postgres | `safe-sender-postgres-1`    | 5432 (internal) |
| nginx    | `safe-sender-nginx-1`       | 80, 443 |

### Known gotchas

* **`docker compose restart` does NOT pick up a new image.** Always `stop && rm && up -d` after a rebuild.
* SSH `docker compose up -d` over a foreground terminal hangs because it inherits the daemon's stdout. Run it as a background session.
* The `nginx` image is multi-stage and includes `dashboard/dist`. Any FE change requires `docker compose build nginx`.
* SES is in sandbox today (2026-05-22) — only verified identities can receive mail. Removal request submitted.
