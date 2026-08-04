"""mitmproxy addon that writes bounded request/response records as JSON Lines."""

from __future__ import annotations

import json
import os
from pathlib import Path

from mitmproxy import http


MAX_BODY = 1024 * 1024
OUTPUT = Path(os.environ["MSW_MITM_OUTPUT"])
ALLOWED_CLIENT_IP = os.getenv("MSW_MITM_ALLOWED_CLIENT_IP")


def _text(content: bytes | None) -> str:
    if not content:
        return ""
    return content[:MAX_BODY].decode("utf-8", errors="replace")


def request(flow: http.HTTPFlow) -> None:
    source_ip = str(flow.client_conn.peername[0]) if flow.client_conn.peername else ""
    if ALLOWED_CLIENT_IP and source_ip != ALLOWED_CLIENT_IP:
        flow.kill()


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
