FROM python:3.12-slim

WORKDIR /app

# F-53 — hash-pinned install via lockfile.
COPY requirements.txt requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

COPY . .

# Container intentionally runs as root: needs to bind privileged ports 25 and 587.
# Avoiding root would require either setcap CAP_NET_BIND_SERVICE on the python
# binary (fragile across Python image updates) or sysctl net.ipv4.ip_unprivileged_port_start=0
# in compose (which weakens the container's port-binding policy globally). Container is
# tightly scoped: only listens on SMTP ports, no shell access, no secrets baked in.
# nosemgrep: dockerfile.security.missing-user.missing-user
CMD ["python", "main.py"]

