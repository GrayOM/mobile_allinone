from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from backend.app import mcp_server


def _transport(seen: list[httpx.Request]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/healthz":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/api/evidence/abc/download":
            return httpx.Response(
                200,
                content=b"\x89PNG\r\n\x1a\nfake",
                headers={
                    "content-type": "image/png",
                    "content-disposition": 'attachment; filename="01-app.png"',
                },
            )
        if request.url.path == "/api/projects/p1/apps/upload":
            return httpx.Response(201, json={"id": "app-1", "bytes": len(request.content)})
        if request.url.path == "/api/runs/r1":
            return httpx.Response(200, json={"id": "r1", "status": "safely_paused"})
        return httpx.Response(
            200,
            json={"path": request.url.path, "query": dict(request.url.params), "method": request.method},
        )

    return httpx.MockTransport(handler)


@pytest.fixture()
def bridge(monkeypatch):
    seen: list[httpx.Request] = []

    def client() -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=_transport(seen),
            base_url="http://127.0.0.1:8765",
            headers={"Authorization": "Bearer test-token"},
        )

    monkeypatch.setattr(mcp_server, "_client", client)
    return seen


def test_api_path_normalization():
    assert mcp_server._api_path("devices") == "/api/devices"
    assert mcp_server._api_path("/api/runs/x") == "/api/runs/x"
    assert mcp_server._api_path("healthz") == "/healthz"


@pytest.mark.asyncio
async def test_get_and_post_forward_json_and_auth(bridge):
    result = json.loads(await mcp_server.msw_get("coverage", {"run_id": "r1", "scope": "run"}))
    assert result["status"] == 200
    assert result["body"]["path"] == "/api/coverage"
    assert result["body"]["query"] == {"run_id": "r1", "scope": "run"}
    assert bridge[-1].headers["authorization"] == "Bearer test-token"

    posted = json.loads(await mcp_server.msw_post("/runs/r1/pause", {}, method="post"))
    assert posted["body"]["method"] == "POST"
    patched = json.loads(await mcp_server.msw_post("/projects/p1", {"name": "x"}, method="PATCH"))
    assert patched["body"]["method"] == "PATCH"
    rejected = json.loads(await mcp_server.msw_post("/projects/p1", {}, method="HEAD"))
    assert rejected["status"] == 0


@pytest.mark.asyncio
async def test_upload_and_download_round_trip(bridge, tmp_path: Path):
    apk = tmp_path / "demo.apk"
    apk.write_bytes(b"PK\x03\x04demo")
    uploaded = json.loads(await mcp_server.msw_upload("projects/p1/apps/upload", str(apk)))
    assert uploaded["status"] == 201
    assert uploaded["body"]["id"] == "app-1"
    assert b"demo.apk" in bridge[-1].content

    missing = json.loads(await mcp_server.msw_upload("projects/p1/apps/upload", str(tmp_path / "nope.apk")))
    assert missing["status"] == 0

    downloaded = json.loads(await mcp_server.msw_download("abc", str(tmp_path / "out")))
    saved = Path(downloaded["path"])
    assert saved.name == "abc-01-app.png"
    assert saved.read_bytes().startswith(b"\x89PNG")
    assert downloaded["content_type"] == "image/png"


@pytest.mark.asyncio
async def test_wait_run_returns_on_safe_pause(bridge):
    result = json.loads(await mcp_server.msw_wait_run("r1", timeout_seconds=5, poll_seconds=1))
    assert result["body"]["status"] == "safely_paused"


def test_routes_resource_lists_core_endpoints():
    text = mcp_server.routes()
    for fragment in ("/runs", "/approvals", "/frida/scripts", "/coverage", "/assessment-controls"):
        assert fragment in text
