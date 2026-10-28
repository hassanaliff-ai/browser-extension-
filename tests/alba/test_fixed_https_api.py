import json
import subprocess
import zipfile

import httpx
import pytest

from scripts import fixed_https_api, start_public_api


def test_tailscale_origin_comes_from_this_device(monkeypatch):
    monkeypatch.setattr(fixed_https_api, "_tailscale_executable", lambda: "tailscale")
    monkeypatch.setattr(
        subprocess, "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, json.dumps({
            "Self": {"DNSName": "basel.example.ts.net."}
        }), ""),
    )
    assert fixed_https_api.tailscale_origin() == "https://basel.example.ts.net"


def test_finalize_requires_protected_public_routes(monkeypatch):
    monkeypatch.setattr(fixed_https_api, "_health", lambda origin: True)
    monkeypatch.setattr(fixed_https_api, "tailscale_origin", lambda: "https://basel.example.ts.net")
    called = []
    monkeypatch.setattr(start_public_api, "package", lambda *args, **kwargs: called.append((args, kwargs)))
    original = httpx.Client

    def respond(request):
        if request.url.path == "/health":
            return httpx.Response(200, json={"api_provider": "SecureScope"})
        if request.url.path == "/monitor/api/devices":
            return httpx.Response(200, json={})
        return httpx.Response(404, json={})

    monkeypatch.setattr(fixed_https_api.httpx, "Client", lambda **kwargs: original(
        transport=httpx.MockTransport(respond), **kwargs
    ))
    with pytest.raises(RuntimeError, match="require sign-in"):
        fixed_https_api.finalize()
    assert called == []


def test_fixed_package_describes_stable_address(tmp_path, monkeypatch):
    monkeypatch.setattr(start_public_api, "ROOT", tmp_path)
    extension = tmp_path / "extension"
    extension.mkdir()
    (extension / "core.js").write_text(
        "export const API_ORIGIN = 'http://127.0.0.1:8765';\nexport const VERSION = 'test';"
    )
    (extension / "manifest.json").write_text(json.dumps({
        "version": "test", "content_security_policy": {
            "extension_pages": "script-src 'self'; connect-src http://127.0.0.1:8765;"
        }
    }))
    archive = start_public_api.package("https://basel.example.ts.net", fixed=True)
    with zipfile.ZipFile(archive) as package:
        instructions = package.read("INSTALL ON ANOTHER DEVICE.txt").decode()
        assert "fixed public API" in instructions
        assert "fixed ts.net hostname" in instructions
        assert "temporary and changes" not in instructions
