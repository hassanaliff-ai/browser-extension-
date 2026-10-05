"""The upload guard runs before multipart parsing, even without a length header."""

from fastapi import FastAPI, File, UploadFile
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse
import pytest

from alba_security.request_limits import DownloadRequestLimit


async def _consume_request(scope, receive, send):
    while True:
        message = await receive()
        if message["type"] == "http.request" and not message.get("more_body", False):
            break
    await JSONResponse({"ok": True})(scope, receive, send)


def test_declared_oversize_is_rejected_before_body_read():
    client = TestClient(DownloadRequestLimit(_consume_request, max_bytes=5))
    response = client.post("/api/downloads/scan-file", content=b"abcdef")
    assert response.status_code == 413


def test_chunked_oversize_is_rejected_while_streaming():
    client = TestClient(DownloadRequestLimit(_consume_request, max_bytes=5))
    response = client.post("/api/downloads/scan-file", content=(chunk for chunk in (b"abc", b"def")))
    assert response.status_code == 413


def test_other_routes_are_unaffected():
    client = TestClient(DownloadRequestLimit(_consume_request, max_bytes=5))
    response = client.post("/api/scans", content=b"abcdef")
    assert response.status_code == 200


def test_stream_limit_runs_before_multipart_upload_is_parsed():
    app = FastAPI()
    app.add_middleware(DownloadRequestLimit, max_bytes=110)

    @app.post("/api/downloads/scan-file")
    async def upload(file: UploadFile = File(...)):
        return {"size": len(await file.read())}

    chunks = (
        b"--x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a\"\r\n\r\n",
        b"x" * 100,
        b"\r\n--x--\r\n",
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/downloads/scan-file",
            headers={"Content-Type": "multipart/form-data; boundary=x"},
            content=(chunk for chunk in chunks),
        )
    assert response.status_code == 413


@pytest.mark.parametrize("route", ["/api/downloads/scan-file", "/api/admin/downloads/scan-file"])
@pytest.mark.parametrize("chunked", [False, True])
def test_mounted_monitoring_uploads_remain_size_limited(route, chunked):
    app = FastAPI()
    app.mount("/monitor", DownloadRequestLimit(_consume_request, max_bytes=5))
    with TestClient(app) as client:
        body = (chunk for chunk in (b"abc", b"def")) if chunked else b"abcdef"
        response = client.post("/monitor" + route, content=body)
        assert response.status_code == 413
        assert response.json()["detail"] == "Download scan request exceeds the size limit"


@pytest.mark.parametrize("route", ["/api/downloads/scan-file", "/api/admin/downloads/scan-file"])
def test_exact_limit_succeeds_under_nested_mount(route):
    app = FastAPI()
    inner = FastAPI()
    inner.mount("/monitor", DownloadRequestLimit(_consume_request, max_bytes=5))
    app.mount("/security", inner)
    with TestClient(app) as client:
        assert client.post("/security/monitor" + route, content=b"abcde").status_code == 200


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_invalid_limit_rejected_at_startup(limit):
    with pytest.raises(ValueError):
        DownloadRequestLimit(_consume_request, max_bytes=limit)
