#!/usr/bin/env python3
"""
Entrypoint: resolve DB hostname to IP before starting uvicorn.

On WSL2, Docker's embedded DNS (127.0.0.11) is unreachable from within
asyncio's thread-pool executor (loop.getaddrinfo hangs indefinitely).
Resolving synchronously here, before the event loop starts, writes the IP
directly into DATABASE_URL so asyncpg never needs to call getaddrinfo.
"""
import os
import socket
import sys
from urllib.parse import urlparse, urlunparse


def resolve_db_url(url: str) -> str:
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return url
    try:
        ip = socket.gethostbyname(hostname)
        at_idx = parsed.netloc.rfind("@")
        if at_idx != -1:
            host_part = parsed.netloc[at_idx + 1:]
            new_host_part = host_part.replace(hostname, ip, 1)
            new_netloc = parsed.netloc[:at_idx + 1] + new_host_part
            resolved = urlunparse(parsed._replace(netloc=new_netloc))
            print(f"[entrypoint] Resolved {hostname} -> {ip}", flush=True)
            return resolved
    except Exception as e:
        print(f"[entrypoint] WARNING: could not resolve {hostname}: {e}", file=sys.stderr, flush=True)
    return url


if __name__ == "__main__":
    db_url = os.environ.get("DATABASE_URL", "")
    if db_url:
        os.environ["DATABASE_URL"] = resolve_db_url(db_url)

    # Ensure the app directory is in the Python path
    app_dir = "/app"
    if app_dir not in sys.path:
        sys.path.insert(0, app_dir)
    os.chdir(app_dir)

    # Replace this process with uvicorn
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, loop="asyncio")
