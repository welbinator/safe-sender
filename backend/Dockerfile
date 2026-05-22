FROM python:3.12-slim

WORKDIR /app

# F-53 — install from the hash-pinned lockfile, not the loose requirements
# file. `--require-hashes` is implicit when every line in the input has a
# hash, and it fails the build if a mirror returns a tampered wheel.
COPY requirements.txt requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

COPY . .

COPY entrypoint.sh /entrypoint.sh
COPY entrypoint.py /entrypoint.py
RUN chmod +x /entrypoint.sh

# Run as non-root for least privilege.
RUN useradd --create-home --shell /bin/bash --uid 10001 app \
    && chown -R app:app /app
USER app

ENTRYPOINT ["python3", "/entrypoint.py"]
