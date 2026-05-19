#!/bin/sh
# Resolve the postgres hostname to an IP and rewrite DATABASE_URL before
# uvicorn starts. On WSL2, Docker's embedded DNS (127.0.0.11) is unreachable
# from within asyncio's thread-pool executor, but getent works fine in a
# shell before the Python event loop is created.

set -e

if [ -n "$DATABASE_URL" ]; then
    # Use Python to safely parse the URL (handles passwords containing @)
    RESOLVED=$(python3 - <<'PYEOF'
import os, sys, socket
from urllib.parse import urlparse, urlunparse

url = os.environ["DATABASE_URL"]
parsed = urlparse(url)
hostname = parsed.hostname
if hostname:
    try:
        ip = socket.gethostbyname(hostname)
        # Rebuild netloc: user:password@IP:port
        netloc = parsed.netloc
        # Replace last @hostname occurrence (handles @ in passwords)
        at_idx = netloc.rfind("@")
        if at_idx != -1:
            host_part = netloc[at_idx+1:]  # hostname:port or just hostname
            new_host_part = host_part.replace(hostname, ip, 1)
            new_netloc = netloc[:at_idx+1] + new_host_part
            url = urlunparse(parsed._replace(netloc=new_netloc))
        print(url)
        sys.exit(0)
    except Exception as e:
        print(f"[entrypoint] WARNING: could not resolve {hostname}: {e}", file=sys.stderr)
print(url)
PYEOF
)
    if [ -n "$RESOLVED" ]; then
        echo "[entrypoint] DATABASE_URL hostname resolved to IP"
        export DATABASE_URL="$RESOLVED"
    fi
fi

exec uvicorn main:app --host 0.0.0.0 --port 8000 --loop asyncio "$@"
