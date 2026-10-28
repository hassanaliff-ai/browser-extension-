"""Prepare and verify a stable Tailscale Funnel for the local SecureScope API.

The prepare command only starts a loopback gateway. Enabling public Funnel is
an explicit, separate Tailscale action. Finalize packages the extension only
after the public address and protected-route behavior have been checked.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
LOCAL = "http://127.0.0.1:8765"
GATEWAY = "http://127.0.0.1:8768"
PRIVATE = ROOT / ".private" / "fixed-api"


def _health(origin: str) -> bool:
    try:
        with httpx.Client(timeout=5, trust_env=False) as client:
            response = client.get(origin + "/health")
        data = response.json()
        return response.status_code == 200 and data.get("api_provider") == "SecureScope"
    except (httpx.HTTPError, ValueError):
        return False


def prepare() -> None:
    if not _health(LOCAL):
        raise RuntimeError("Start the local SecureScope API before preparing HTTPS access.")
    if _health(GATEWAY):
        print("SecureScope loopback gateway is ready on port 8768.")
        return
    PRIVATE.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ, EXTSECURE_PUBLIC_GATEWAY="tailscale")
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    with (PRIVATE / "gateway.log").open("ab") as log:
        child = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "scripts.lan_gateway:app", "--host", "127.0.0.1", "--port", "8768", "--no-proxy-headers", "--no-access-log"],
            cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
            stdout=log, stderr=log, creationflags=flags,
        )
    for _ in range(30):
        if child.poll() is not None:
            break
        if _health(GATEWAY):
            (PRIVATE / "gateway.pid").write_text(str(child.pid), encoding="ascii")
            print("SecureScope loopback gateway is ready on port 8768.")
            return
        time.sleep(0.25)
    raise RuntimeError("Gateway did not start; inspect .private/fixed-api/gateway.log.")


def _tailscale_executable() -> str:
    binary = shutil.which("tailscale")
    if binary:
        return binary
    windows = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Tailscale" / "tailscale.exe"
    if windows.is_file():
        return str(windows)
    raise RuntimeError("Install and sign in to Tailscale before finalizing the fixed HTTPS address.")


def tailscale_origin() -> str:
    result = subprocess.run(
        [_tailscale_executable(), "status", "--json"],
        capture_output=True, text=True, timeout=15, check=True,
    )
    name = json.loads(result.stdout).get("Self", {}).get("DNSName", "").rstrip(".").lower()
    if not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+\.ts\.net", name):
        raise RuntimeError("Tailscale did not report a valid ts.net device hostname.")
    return "https://" + name


def finalize() -> str:
    if not _health(LOCAL) or not _health(GATEWAY):
        raise RuntimeError("Start the SecureScope API and loopback gateway first.")
    origin = tailscale_origin()
    with httpx.Client(timeout=10, trust_env=False) as client:
        response = client.get(origin + "/health")
        if response.status_code != 200 or response.json().get("api_provider") != "SecureScope":
            raise RuntimeError("The public HTTPS address does not reach SecureScope.")
        if client.get(origin + "/monitor/api/devices").status_code != 401:
            raise RuntimeError("The protected API route did not require sign-in.")
        if client.get(origin + "/docs").status_code != 404:
            raise RuntimeError("The public gateway exposed an unexpected route.")
    from scripts.start_public_api import package

    archive = package(origin, fixed=True)
    print(f"Verified {origin}; extension package: {archive}")
    return origin


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("prepare", "finalize"))
    arguments = parser.parse_args()
    if arguments.action == "prepare":
        prepare()
    else:
        finalize()
