# S-L6: pin base image by digest so a future python:3.12-slim re-tag can't
# silently introduce a new userland/OpenSSL into prod. To bump: run
#   docker pull python:3.12-slim && docker inspect --format '{{index .RepoDigests 0}}' python:3.12-slim
# and replace the digest below. Last bumped 2026-05 -> python:3.12-slim.
FROM python:3.12-slim@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203

WORKDIR /app

# F-53 — hash-pinned install via lockfile.
COPY smtp/requirements.txt smtp/requirements.lock /app/
RUN pip install --no-cache-dir --require-hashes -r /app/requirements.lock

# S-L4 — shared F-17 crypto package (single source of truth).
COPY shared/safesender_crypto /usr/local/lib/python3.12/site-packages/safesender_crypto
COPY shared/ai_scan.py /app/ai_scan.py

COPY smtp/ /app/

# S-M3 — non-root runtime.
#
# We can't `USER app` here because two things must happen as root first:
#   1. Bind privileged ports 25 and 587.
#   2. Read the Let's Encrypt private key (0600 root:root) into an SSLContext.
# Instead we create the unprivileged 'app' account here and main.py calls
# os.setgid/setuid to drop to it AFTER sockets are bound and TLS material is
# loaded into memory. This is the classic sshd / postfix / nginx pattern:
# minimal root window, long-lived process runs unprivileged.
RUN groupadd --system --gid 10001 app \
    && useradd  --system --uid 10001 --gid app --home /app --shell /sbin/nologin app \
    && chown -R app:app /app

CMD ["python", "main.py"]
