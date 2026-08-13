"""mitmproxy addon that writes bounded request/response records as JSON Lines."""

from __future__ import annotations

import json
import os
from pathlib import Path

from mitmproxy import http


MAX_BODY = 1024 * 1024
OUTPUT = Path(os.environ["MSW_MITM_OUTPUT"])
ALLOWED_CLIENT_IP = os.getenv("MSW_MITM_ALLOWED_CLIENT_IP")
_ALLOWED_HOSTS_RAW = os.getenv("MSW_MITM_ALLOWED_HOSTS")
try:
    _parsed_allowed_hosts = json.loads(_ALLOWED_HOSTS_RAW) if _ALLOWED_HOSTS_RAW else None
except json.JSONDecodeError:
    _parsed_allowed_hosts = []
ALLOWED_HOSTS = (
    tuple(str(item).lower().rstrip(".") for item in _parsed_allowed_hosts)
    if isinstance(_parsed_allowed_hosts, list)
    else None
)


def _text(content: bytes | None) -> str:
    if not content:
        return ""
    return content[:MAX_BODY].decode("utf-8", errors="replace")


def _host_allowed(host: str) -> bool:
    candidate = host.lower().rstrip(".")
    for rule in ALLOWED_HOSTS or ():
        if rule.startswith("*."):
            suffix = rule[1:]
            if candidate.endswith(suffix) and candidate != rule[2:]:
                return True
        elif candidate == rule:
            return True
    return False


def request(flow: http.HTTPFlow) -> None:
    source_ip = str(flow.client_conn.peername[0]) if flow.client_conn.peername else ""
    if ALLOWED_CLIENT_IP and source_ip != ALLOWED_CLIENT_IP:
        flow.kill()
        return
    if ALLOWED_HOSTS is not None and not _host_allowed(flow.request.host):
        flow.response = http.Response.make(
            451,
            b'{"error":"outside_approved_control_scope"}',
            {
                "Content-Type": "application/json",
                "X-MSW-Control-Scope": "blocked",
                "Cache-Control": "no-store",
            },
        )


def response(flow: http.HTTPFlow) -> None:
    source_ip = str(flow.client_conn.peername[0]) if flow.client_conn.peername else ""
    if ALLOWED_CLIENT_IP and source_ip != ALLOWED_CLIENT_IP:
        return
    record = {
        "method": flow.request.method,
        "url": flow.request.pretty_url,
        "request_headers": dict(flow.request.headers.items(multi=True)),
        "request_body": _text(flow.request.content),
        "status_code": flow.response.status_code if flow.response else None,
        "response_headers": (
            dict(flow.response.headers.items(multi=True)) if flow.response else {}
        ),
        "response_body": _text(flow.response.content if flow.response else None),
        "source_ip": source_ip,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=False) + "\n")
