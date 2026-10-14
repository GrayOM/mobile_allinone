"""MCP bridge so a Claude Code session can operate the local workbench.

The bridge is a thin HTTP client: it forwards requests to the running
FastAPI server (``MSW_BASE_URL``, loopback by default) and exposes the API
route list as a resource. Every safety boundary (approval tokens, run
state checks, scope validation) stays in the server; nothing is bypassed
here. Run it with ``python -m backend.app.mcp_server`` from ``.mcp.json``.
"""

from __future__ import annotations

import json
import mimetypes
import os
from pathlib import Path
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

BASE_URL = os.getenv("MSW_BASE_URL", "http://127.0.0.1:8765").rstrip("/")
API_TOKEN = os.getenv("MSW_API_TOKEN") or None
TIMEOUT = float(os.getenv("MSW_MCP_TIMEOUT_SECONDS", "180"))
DOWNLOAD_DIR = Path(
    os.getenv("MSW_MCP_DOWNLOAD_DIR", Path.cwd() / "data" / "mcp-downloads")
)
MAX_INLINE_BYTES = 256 * 1024

mcp = FastMCP(
    "mobile-security-workbench",
    instructions=(
        "Local mobile app security workbench. Read the 'msw://routes' resource "
        "first, then call msw_get / msw_post / msw_upload / msw_download with "
        "paths under /api. Approval tokens, run states and scope checks are "
        "enforced by the server; a 4xx response explains what is missing."
    ),
)


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {API_TOKEN}"} if API_TOKEN else {}


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=BASE_URL, headers=_headers(), timeout=TIMEOUT)


def _api_path(path: str) -> str:
    cleaned = "/" + path.strip().lstrip("/")
    if cleaned == "/healthz":
        return cleaned
    if not cleaned.startswith("/api/"):
        cleaned = "/api" + cleaned
    return cleaned


def _unreachable(exc: Exception) -> str:
    return json.dumps(
        {
            "status": 0,
            "error": f"workbench unreachable at {BASE_URL}: {exc}",
            "hint": "Start the server first (scripts/run.sh or run_windows.ps1) or set MSW_BASE_URL.",
        },
        ensure_ascii=False,
    )


def _render(response: httpx.Response) -> str:
    body: Any
    try:
        body = response.json()
    except ValueError:
        body = response.text[:MAX_INLINE_BYTES]
    payload = {"status": response.status_code, "body": body}
    text = json.dumps(payload, ensure_ascii=False, indent=1, default=str)
    if len(text) > MAX_INLINE_BYTES:
        text = text[:MAX_INLINE_BYTES] + "\n…(truncated)"
    return text


@mcp.tool()
async def msw_get(path: str, params: dict[str, Any] | None = None) -> str:
    """GET an API path (e.g. /api/devices, /api/runs/{id}, /api/coverage?run_id=…)."""
    try:
        async with _client() as client:
            response = await client.get(_api_path(path), params=params or None)
    except httpx.HTTPError as exc:
        return _unreachable(exc)
    return _render(response)


@mcp.tool()
async def msw_post(
    path: str,
    body: dict[str, Any] | None = None,
    method: str = "POST",
) -> str:
    """Send a JSON request (POST by default; PATCH/PUT/DELETE via ``method``)."""
    verb = method.upper()
    if verb not in {"POST", "PATCH", "PUT", "DELETE"}:
        return json.dumps({"status": 0, "error": "method must be POST, PATCH, PUT or DELETE"})
    try:
        async with _client() as client:
            response = await client.request(verb, _api_path(path), json=body)
    except httpx.HTTPError as exc:
        return _unreachable(exc)
    return _render(response)


@mcp.tool()
async def msw_upload(path: str, file_path: str, field: str = "file") -> str:
    """Upload a local file as multipart (app APK/IPA, HAR import, assessment evidence)."""
    source = Path(file_path).expanduser().resolve()
    if not source.is_file():
        return json.dumps({"status": 0, "error": f"file not found: {source}"})
    content_type = mimetypes.guess_type(source.name)[0] or "application/octet-stream"
    try:
        async with _client() as client:
            with source.open("rb") as stream:
                response = await client.post(
                    _api_path(path),
                    files={field: (source.name, stream, content_type)},
                )
    except httpx.HTTPError as exc:
        return _unreachable(exc)
    return _render(response)


@mcp.tool()
async def msw_download(evidence_id: str, destination_dir: str | None = None) -> str:
    """Download an evidence file (screenshot, archive, report) to a local directory and return its path."""
    target_dir = Path(destination_dir).expanduser() if destination_dir else DOWNLOAD_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    try:
        async with _client() as client:
            meta = await client.get(f"/api/evidence/{evidence_id}/download")
    except httpx.HTTPError as exc:
        return _unreachable(exc)
    if meta.status_code != 200:
        return _render(meta)
    disposition = meta.headers.get("content-disposition", "")
    name = evidence_id
    if "filename=" in disposition:
        name = disposition.split("filename=")[-1].strip('"; ')
    destination = target_dir / f"{evidence_id[:8]}-{Path(name).name}"
    destination.write_bytes(meta.content)
    return json.dumps(
        {
            "status": 200,
            "path": str(destination),
            "bytes": destination.stat().st_size,
            "content_type": meta.headers.get("content-type"),
        },
        ensure_ascii=False,
    )


@mcp.tool()
async def msw_wait_run(run_id: str, timeout_seconds: int = 600, poll_seconds: int = 3) -> str:
    """Poll a run until it reaches safely_paused or a terminal state; returns the run."""
    import asyncio

    terminal = {
        "safely_paused",
        "completed",
        "completed_with_gaps",
        "manual_required",
        "failed",
        "stopped",
        "interrupted",
    }
    deadline = asyncio.get_event_loop().time() + max(5, min(timeout_seconds, 3600))
    last: str = ""
    async with _client() as client:
        while asyncio.get_event_loop().time() < deadline:
            try:
                response = await client.get(f"/api/runs/{run_id}")
            except httpx.HTTPError as exc:
                return _unreachable(exc)
            last = _render(response)
            if response.status_code != 200:
                return last
            if response.json().get("status") in terminal:
                return last
            await asyncio.sleep(max(1, poll_seconds))
    return last


ROUTES_DOC = """# Workbench API map (all under /api)

## Projects / apps
GET  /projects · POST /projects {name, run_mode: mock|live, assessment_profile, ai_enabled, external_ai_allowed, external_analyzer_allowed}
GET  /projects/{id} · PATCH /projects/{id} · DELETE /projects/{id}
GET  /projects/{id}/apps · POST /projects/{id}/apps/upload (multipart file: .apk/.ipa) → msw_upload
POST /apps/{id}/reanalyze · GET /apps/{id}/analysis/overview · POST /apps/{id}/ai/triage
GET  /apps/{id}/assessment/plan · POST /apps/{id}/assessment/plan/refresh
GET  /projects/{id}/assessment-scope · POST /projects/{id}/custom-controls · PUT/DELETE /projects/{id}/control-exclusions/{control_id}

## Devices
GET  /devices · POST /devices/action {adapter, device_id, action, package_name?, app_id?, project_id?, run_id?, approval_token?}
GET  /devices/ios/profiles · POST /devices/ios/profiles

## Runs
POST /runs {project_id, app_id, device_id, device_adapter, proxy_adapter, frida_script_ids[], auto_select_frida, pause_for_login, options{}}
     options: frida_mode spawn|attach, auto_navigation, dynamic_storage, background_screen_check,
              pause_for_approval_candidates, pause_for_security_bypass, control_validation{…} (live scope)
GET  /runs/{id} · GET /projects/{id}/runs · POST /runs/{id}/pause|resume|stop → msw_wait_run to block
GET  /runs/{id}/evidence · GET /evidence/{id}/download (msw_download) · GET /runs/{id}/flows · GET /runs/{id}/flows/raw
GET  /runs/{id}/frida/health · POST /runs/{id}/proxy/confirm-setup · POST /runs/{id}/proxy/import (multipart .har)
GET  /runs/{id}/ui-action-candidates · POST /runs/{id}/ui-action-candidates/{cid}/execute {approval_token}
GET  /runs/{id}/component-candidates · POST /runs/{id}/component-candidates/{cid}/verify {approval_token}
POST /runs/{id}/network-candidates/{cid}/execute {approval_token}
POST /runs/{id}/tls-scan {targets[≤5]} · POST /runs/{id}/ai/evidence-priority
POST /runs/{id}/report/docx · GET /runs/{id}/report/docx

## Approvals (5-minute, single use; issued only for safely_paused runs)
POST /approvals {project_id, run_id, resource_type: device|runtime|frida|component|ui_action|network_candidate, action, approved_by, candidate_id?}

## Frida
GET  /frida/scripts · POST /frida/scripts {name, platform, category, target_framework, conditions[], risk, content}
POST /frida/scripts/{id}/approve {approver, review_acknowledged: true, reviewed_sha256}
POST /frida/scripts/{id}/execute {project_id, run_id, mode, approval_token}
POST /frida/scripts/generate {project_id, run_id?, app_id?, purpose, platform, …} · GET /frida/runtime

## Runtime tools / findings / ledger
GET  /runtime/adapters · POST /runtime/execute {adapter, project_id, run_id, action, arguments, approval_token?}
GET  /findings?project_id|run_id · GET /findings/{id} · GET /findings/{id}/sources · GET /findings/{id}/report
GET  /coverage?run_id=…&scope=run&standard=critical_infrastructure|electronic_financial|owasp_mastg
POST /assessment-controls/{control_test_id}/record {outcome, reviewer, summary, evidence_ids[], criteria_confirmed}
POST /assessment-controls/{control_test_id}/evidence (multipart png/jpg/txt/log/json/xml/har)
GET  /assessment/profiles · GET /assessment/execution-matrix?profile= · GET /assessment/guidance/{profile}/{control_id}

## Settings
GET  /settings · PUT /settings/tools · GET /analysis/tools · GET /proxy/adapters · GET /ios/signing · POST /apps/{id}/ios/resign
GET  /healthz (no /api prefix)
"""


@mcp.resource("msw://routes")
def routes() -> str:
    """Route map of the workbench API for use with msw_get / msw_post."""
    return ROUTES_DOC


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
