FROM python:3.12-slim

WORKDIR /app

# F-53 — install from the hash-pinned lockfile, not the loose requirements
# file. `--require-hashes` is implicit when every line in the input has a
# hash, and it fails the build if a mirror returns a tampered wheel.
COPY backend/requirements.txt backend/requirements.lock /app/
RUN pip install --no-cache-dir --require-hashes -r /app/requirements.lock

# S-L4 — install the shared crypto package as the single source of truth
# for F-17 KDF parameters. Drop it into site-packages so backend and smtp
# can both `from safesender_crypto import ...` without sys.path tricks.
COPY shared/safesender_crypto /usr/local/lib/python3.12/site-packages/safesender_crypto

COPY backend/ /app/

COPY backend/entrypoint.sh /entrypoint.sh
COPY backend/entrypoint.py /entrypoint.py
RUN chmod +x /entrypoint.sh

# Run as non-root for least privilege.
RUN useradd --create-home --shell /bin/bash --uid 10001 app \
    && chown -R app:app /app
USER app

ENTRYPOINT ["python3", "/entrypoint.py"]
