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


def resolve_db_url(url: str):
    """Returns (resolved_url, hostname, ip). ip may equal hostname if resolution failed."""
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return url, None, None
    try:
        ip = socket.gethostbyname(hostname)
        at_idx = parsed.netloc.rfind("@")
        if at_idx != -1:
            host_part = parsed.netloc[at_idx + 1:]
            new_host_part = host_part.replace(hostname, ip, 1)
            new_netloc = parsed.netloc[:at_idx + 1] + new_host_part
            resolved = urlunparse(parsed._replace(netloc=new_netloc))
            print(f"[entrypoint] Resolved {hostname} -> {ip}", flush=True)
            return resolved, hostname, ip
    except Exception as e:
        print(f"[entrypoint] WARNING: could not resolve {hostname}: {e}", file=sys.stderr, flush=True)
    return url, hostname, None


if __name__ == "__main__":
    import time

    # Wait until network is fully up (IP is assigned in the container).
    # On some Docker/kernel combos the container starts before the network
    # namespace is fully initialised, leaving the interface with no IP.
    for i in range(30):
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect(("8.8.8.8", 53))
            s.close()
            print(f"[entrypoint] Network ready after {i}s", flush=True)
            break
        except OSError:
            if i == 0:
                print("[entrypoint] Waiting for network...", flush=True)
            time.sleep(1)

    db_url = os.environ.get("DATABASE_URL", "")
    if db_url:
        resolved, hostname, ip = resolve_db_url(db_url)
        os.environ["DATABASE_URL"] = resolved
        # Write the IP into /etc/hosts so thread-pool DNS finds it without
        # contacting Docker's embedded DNS (127.0.0.11), which is unreachable
        # from executor threads on WSL2.
        if hostname and ip and hostname != ip:
            try:
                with open("/etc/hosts", "a") as f:
                    f.write(f"\n{ip} {hostname}\n")
                print(f"[entrypoint] Added {ip} {hostname} to /etc/hosts", flush=True)
            except Exception as e:
                print(f"[entrypoint] Could not write /etc/hosts: {e}", file=sys.stderr, flush=True)

    # Ensure the app directory is in the Python path
    app_dir = "/app"
    if app_dir not in sys.path:
        sys.path.insert(0, app_dir)
    os.chdir(app_dir)

    # Replace this process with uvicorn
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, loop="asyncio")
