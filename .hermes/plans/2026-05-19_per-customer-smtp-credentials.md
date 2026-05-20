# Sprint 7 — Per-Customer SMTP Credentials

## Goal
Each customer gets their own unique SMTP username + password for authenticating to `smtp.sendersafety.com`. Credentials are generated at signup, stored in the DB, displayed in the dashboard, and can be rotated. The global `AUTH_USERNAME`/`AUTH_PASSWORD` env vars are retired as the auth mechanism.

## Current State
- Single `AUTH_USERNAME` / `AUTH_PASSWORD` in `.env` — shared by all customers
- SMTP authenticator checks against those env vars directly
- No per-customer revocation or rotation possible
- Credentials not shown in dashboard at all

## Proposed Approach
- Add `smtp_username` + `smtp_password_hash` columns to `customers` table
- On signup (or migration for existing accounts), generate `smtp_username = ss_<random_hex>`, hash a random password with bcrypt
- SMTP authenticator queries the DB by username, verifies password hash
- Backend: expose `GET /customers/me/smtp-credentials` (returns username + plaintext password — only shown once on generation) and `POST /customers/me/smtp-credentials/rotate`
- Dashboard: new "SMTP Credentials" widget — shows username, masked password with "reveal" and "rotate" buttons

## Step-by-Step Plan

### 1. DB Migration
File: `backend/migrations/005_smtp_credentials.sql`
```sql
ALTER TABLE customers
  ADD COLUMN smtp_username TEXT UNIQUE,
  ADD COLUMN smtp_password_hash TEXT;
```

### 2. Backfill existing customers + auto-generate on signup
File: `backend/routers/auth.py`
- In the `POST /auth/google` handler, after creating a new customer (`is_new=True`), generate credentials:
  ```python
  import secrets, bcrypt
  smtp_username = "ss_" + secrets.token_hex(8)
  raw_password = secrets.token_urlsafe(16)
  smtp_password_hash = bcrypt.hashpw(raw_password.encode(), bcrypt.gensalt()).decode()
  # store in DB
  # return raw_password in response (only time it's available in plaintext)
  ```
- Add `bcrypt` to `requirements.txt`

### 3. SMTP Authenticator rewrite
File: `smtp/main.py`
- Replace `Authenticator.__call__` env-var check with async DB lookup:
  - On AUTH, query backend: `GET /internal/smtp-auth?username=<u>&password=<p>`
  - Backend verifies bcrypt hash, returns `{"customer_id": ..., "domain": ...}` or 401
- Keep `AUTH_USERNAME`/`AUTH_PASSWORD` env vars as a fallback admin credential (for testing/ops)

### 4. Backend internal auth endpoint
File: `backend/main.py`
```
GET /internal/smtp-auth?username=<u>&password=<p>
```
- Look up customer by `smtp_username`
- bcrypt verify password
- Return `{"customer_id": ..., "domain": ...}` or 401

### 5. Customer credentials API
File: `backend/routers/customers.py`
```
GET  /customers/me/smtp-credentials   → { username, smtp_host, smtp_port }
                                          (never returns password — rotate to get new one)
POST /customers/me/smtp-credentials/rotate → { username, password }
                                              (generates new password, returns plaintext once)
```

### 6. Dashboard widget
File: `dashboard/src/widgets/SmtpCredentials.jsx`
- Shows:
  - SMTP Host: `smtp.sendersafety.com`
  - Port: `587`
  - Username: `ss_xxxxxxxxxxxxxxxx`
  - Password: `••••••••` with "Rotate" button
- Rotate button calls API, reveals new password once with a "copy" button and warning "Save this — it won't be shown again"
- Add widget to Setup Guide (step 3 — after domain verification)

### 7. Migration script for existing customers
File: `backend/migrations/005_smtp_credentials_backfill.py` (one-time script)
- Query all customers with `smtp_username IS NULL`
- Generate credentials, update rows
- Print credentials to stdout so they can be manually communicated to existing customers

## Files to Change
- `backend/migrations/005_smtp_credentials.sql` (new)
- `backend/requirements.txt` (add `bcrypt`)
- `backend/routers/auth.py` (generate creds on signup)
- `backend/routers/customers.py` (credentials + rotate endpoints)
- `backend/main.py` (add `/internal/smtp-auth` endpoint)
- `smtp/main.py` (Authenticator queries DB via backend)
- `dashboard/src/widgets/SmtpCredentials.jsx` (new)
- `dashboard/src/api.js` (add getSmtpCredentials, rotateSmtpCredentials)
- `dashboard/src/App.jsx` or layout (add widget to setup guide / dashboard)

## Risks & Notes
- bcrypt verify happens on every SMTP AUTH — it's slightly slow (~100ms) but auth only happens once per connection, acceptable
- Password is only ever returned in plaintext at generation/rotation time — after that it's hash-only in DB
- Keep env-var fallback (`AUTH_USERNAME`/`AUTH_PASSWORD`) so you can still test/debug without a customer account
- Existing customers (there are 2 in DB currently) need backfilled credentials — use the migration script, note them down

## Validation
1. Sign up fresh account → response includes SMTP password (one time)
2. Configure relay with those credentials → send test email → appears in logs
3. Rotate password → old credentials rejected → new ones work
4. Delete/unverify customer → their credentials stop working
