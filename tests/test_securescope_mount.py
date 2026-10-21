"""The development server can serve both teams' APIs in one process."""

from fastapi.testclient import TestClient

import main


def test_securescope_is_not_mounted_by_default(monkeypatch):
    monkeypatch.delenv("SECURESCOPE_DEV_ENABLED", raising=False)
    with TestClient(main.create_app()) as client:
        assert client.get("/securescope/health").status_code == 404


def test_combined_server_serves_both_apis_and_local_docs(monkeypatch):
    monkeypatch.setenv("SECURESCOPE_DEV_ENABLED", "1")
    extension_id = "a" * 32
    monkeypatch.setenv("SECURESCOPE_ALLOWED_EXTENSION_ID", extension_id)
    with TestClient(main.create_app()) as client:
        assert client.get("/health").json() == {"status": "ok", "service": "TestAPI"}
        assert client.get("/securescope/health").json() == {"status": "ok"}
        docs = client.get("/securescope/docs")
        assert docs.status_code == 200
        assert "/securescope/openapi.json" in docs.text
        assert "/securescope/static/swagger-ui.css" in docs.text
        assert "/securescope/static/swagger-ui-bundle.js" in docs.text
        assert client.get("/securescope/static/swagger-ui.css").status_code == 200
        assert client.get("/securescope/openapi.json").status_code == 200
        assert client.post("/securescope/api/v1/rdap", headers={
            "Origin": "https://unrelated.example",
        }, json={"origin": "https://example.com"}).status_code == 403
        assert client.post("/securescope/api/v1/check", json={
            "url": "https://example.com", "source": "manual", "checked_at": 0,
        }).status_code == 503
        allowed = client.post("/securescope/api/v1/check", headers={
            "Origin": f"chrome-extension://{extension_id}",
        }, json={"url": "https://example.com", "source": "manual", "checked_at": 0})
        assert allowed.status_code == 503
        assert allowed.headers["access-control-allow-origin"] == f"chrome-extension://{extension_id}"
        preflight = client.options("/securescope/api/v1/check", headers={
            "Origin": f"chrome-extension://{extension_id}",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        })
        assert preflight.status_code == 204
        assert preflight.headers["access-control-allow-origin"] == f"chrome-extension://{extension_id}"
        denied = client.options("/securescope/api/v1/check", headers={
            "Origin": "https://unrelated.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        })
        assert denied.status_code == 403
        assert "access-control-allow-origin" not in denied.headers
        legacy = client.options("/extension/scan", headers={
            "Origin": "https://unrelated.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        })
        assert legacy.headers["access-control-allow-origin"] == "*"
