from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from backend.app.proxy.base import ProxyFlowData

from .models import PassiveFlowAnalysis


ID_KEY_PATTERN = re.compile(r"(^|_)(id|user|account|object|profile)(_|$)", re.I)
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.I,
)
SENSITIVE_KEYS = {
    "authorization",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "password",
    "cookie",
    "session",
    "email",
    "phone",
    "address",
    "account",
    "card",
    "ssn",
}
PAGINATION_KEYS = {"page", "page_size", "limit", "offset", "cursor", "after", "before"}


def _headers(headers: dict[str, str]) -> dict[str, str]:
    return {str(key).casefold(): str(value) for key, value in headers.items()}


def _field_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "string"


def _walk(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    fields: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            fields.append((path, item))
            fields.extend(_walk(item, path))
    elif isinstance(value, list):
        for index, item in enumerate(value[:20]):
            fields.extend(_walk(item, f"{prefix}[{index}]"))
    return fields


def _masked(value: str) -> str:
    if not value:
        return "<empty>"
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}…{value[-2:]}"


def classify_proxy_flow(
    flow: ProxyFlowData,
    *,
    source_flow_id: str,
) -> PassiveFlowAnalysis:
    parsed = urlsplit(flow.url)
    request_headers = _headers(flow.request_headers)
    content_type = request_headers.get("content-type", "").split(";", 1)[0].strip()
    auth_value = request_headers.get("authorization", "")
    auth_scheme = auth_value.split(" ", 1)[0] if auth_value else None
    cookie_value = request_headers.get("cookie", "")
    cookie_names = sorted(
        {
            part.partition("=")[0].strip()
            for part in cookie_value.split(";")
            if part.partition("=")[0].strip()
        }
    )
    query_parameters = []
    object_ids = []
    pagination = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True)[:200]:
        query_parameters.append(
            {"name": key, "type": "string", "masked_value": _masked(value)}
        )
        if key.casefold() in PAGINATION_KEYS:
            pagination.append(key)
        if ID_KEY_PATTERN.search(key) or value.isdigit() or UUID_PATTERN.fullmatch(value):
            object_ids.append(
                {"location": f"query:{key}", "name": key, "masked_value": _masked(value)}
            )
    path_segments = [segment for segment in parsed.path.split("/") if segment]
    normalized_segments = []
    for index, segment in enumerate(path_segments):
        if segment.isdigit() or UUID_PATTERN.fullmatch(segment):
            normalized_segments.append("{id}")
            object_ids.append(
                {
                    "location": f"path:{index}",
                    "name": "path_id",
                    "masked_value": _masked(segment),
                }
            )
        else:
            normalized_segments.append(segment)
    endpoint = "/" + "/".join(normalized_segments)

    body_fields: list[dict[str, Any]] = []
    parsed_body: Any = None
    if "json" in content_type and flow.request_body:
        try:
            parsed_body = json.loads(flow.request_body)
        except (json.JSONDecodeError, TypeError):
            parsed_body = None
    for path, value in _walk(parsed_body)[:500]:
        body_fields.append({"path": path, "type": _field_type(value)})
        name = path.rsplit(".", 1)[-1].split("[", 1)[0]
        if ID_KEY_PATTERN.search(name):
            object_ids.append(
                {
                    "location": f"json:{path}",
                    "name": name,
                    "masked_value": _masked(str(value)),
                }
            )
        if name.casefold() in PAGINATION_KEYS:
            pagination.append(name)

    sensitive_response_fields: list[str] = []
    try:
        response_json = json.loads(flow.response_body) if flow.response_body else None
    except (json.JSONDecodeError, TypeError):
        response_json = None
    for path, _ in _walk(response_json)[:1000]:
        name = path.rsplit(".", 1)[-1].split("[", 1)[0].casefold()
        if any(term in name for term in SENSITIVE_KEYS):
            sensitive_response_fields.append(path)

    graphql = (
        "graphql" in parsed.path.casefold()
        or isinstance(parsed_body, dict)
        and ("query" in parsed_body or "operationName" in parsed_body)
    )
    file_upload = content_type.startswith("multipart/form-data")
    protocol_style = "graphql" if graphql else "rest"
    return PassiveFlowAnalysis(
        source_flow_id=source_flow_id,
        method=flow.method.upper(),
        origin=f"{parsed.scheme}://{parsed.netloc}",
        endpoint=endpoint or "/",
        content_type=content_type,
        auth_scheme=auth_scheme,
        cookie_names=cookie_names,
        query_parameters=query_parameters,
        body_fields=body_fields,
        object_id_candidates=object_ids,
        pagination_parameters=sorted(set(pagination)),
        file_upload=file_upload,
        protocol_style=protocol_style,
        sensitive_response_fields=sorted(set(sensitive_response_fields)),
        synthetic=flow.synthetic,
    )
