from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from backend.app.control_validation import network_host_allowed
from backend.app.core.network import resolved_http_transport
from backend.app.core.status import CapabilityStatus
from backend.app.proxy.base import ProxyFlowData

from .comparator import compare_responses
from .models import NetworkExecution, NetworkTestCandidate


MAX_RESPONSE_BYTES = 1_048_576
HOP_BY_HOP_HEADERS = {
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "accept-encoding",
}


class LiveNetworkExecutionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ResolvedReplayDestination:
    hostname: str
    addresses: tuple[str, ...]


async def resolve_replay_destination(
    url: str, allowed_hosts: list[str]
) -> ResolvedReplayDestination:
    try:
        parsed = urlsplit(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise LiveNetworkExecutionError(f"원본 Flow URL 해석 실패: {exc}") from exc
    hostname = str(parsed.hostname or "").rstrip(".").lower()
    if (
        parsed.scheme not in {"http", "https"}
        or not hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise LiveNetworkExecutionError(
            "읽기 전용 재현은 자격증명이 포함되지 않은 http/https 원본 URL만 허용합니다."
        )
    if not network_host_allowed(hostname, allowed_hosts):
        raise LiveNetworkExecutionError(
            "원본 Flow 목적지가 현재 승인된 테스트 서버 범위 밖입니다."
        )
    loop = asyncio.get_running_loop()
    try:
        records = await asyncio.wait_for(
            loop.getaddrinfo(
                hostname,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            ),
            timeout=5,
        )
    except (OSError, asyncio.TimeoutError) as exc:
        raise LiveNetworkExecutionError(f"승인 목적지 DNS 해석 실패: {exc}") from exc
    addresses = tuple(
        sorted({str(ipaddress.ip_address(record[4][0])) for record in records})
    )
    if not addresses:
        raise LiveNetworkExecutionError(
            "승인 목적지에서 연결 가능한 A/AAAA 주소를 확인할 수 없습니다."
        )
    return ResolvedReplayDestination(hostname, addresses)


def _request_headers(headers: dict[str, str]) -> dict[str, str]:
    result = {
        str(name): str(value)
        for name, value in headers.items()
        if str(name).casefold() not in HOP_BY_HOP_HEADERS
    }
    result["Accept-Encoding"] = "identity"
    return result


class LiveReadOnlyNetworkExecutor:
    """Execute one approved GET/HEAD replay with DNS pinning and hard limits."""

    async def execute(
        self,
        candidate: NetworkTestCandidate,
        source_flow: ProxyFlowData,
        *,
        allowed_hosts: list[str],
    ) -> tuple[NetworkExecution, dict[str, Any]]:
        if (
            candidate.test_type != "read_only_replay"
            or candidate.method not in {"GET", "HEAD"}
            or source_flow.request_body
        ):
            raise LiveNetworkExecutionError(
                "상태 변경 또는 본문이 있는 요청은 승인 후에도 자동 재전송하지 않습니다."
            )
        destination = await resolve_replay_destination(
            source_flow.url, allowed_hosts
        )
        response_headers: dict[str, str] = {}
        response_body = ""
        response_status: int | None = None
        truncated = False
        try:
            transport = resolved_http_transport(
                destination.hostname, destination.addresses
            )
            async with httpx.AsyncClient(
                transport=transport,
                follow_redirects=False,
                trust_env=False,
                timeout=httpx.Timeout(10.0, connect=8.0),
            ) as client:
                async with client.stream(
                    candidate.method,
                    source_flow.url,
                    headers=_request_headers(source_flow.request_headers),
                ) as response:
                    response_status = response.status_code
                    response_headers = dict(response.headers)
                    body = bytearray()
                    async for chunk in response.aiter_raw():
                        remaining = MAX_RESPONSE_BYTES - len(body)
                        if remaining <= 0:
                            truncated = True
                            break
                        body.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            truncated = True
                            break
                    response_body = bytes(body).decode("utf-8", errors="replace")
        except (httpx.HTTPError, OSError, RuntimeError) as exc:
            return (
                NetworkExecution(
                    candidate_id=candidate.id,
                    status=CapabilityStatus.FAILED.value,
                    message=f"승인된 읽기 전용 재현 실패: {type(exc).__name__}: {exc}",
                    synthetic=False,
                ),
                {
                    "hostname": destination.hostname,
                    "resolved_addresses": list(destination.addresses),
                    "response_status": None,
                    "response_headers": {},
                    "response_body": "",
                    "response_truncated": False,
                },
            )

        comparison = compare_responses(
            original_status=source_flow.status_code,
            original_headers=source_flow.response_headers,
            original_body=source_flow.response_body,
            candidate_status=response_status,
            candidate_headers=response_headers,
            candidate_body=response_body,
        )
        execution = NetworkExecution(
            candidate_id=candidate.id,
            status=CapabilityStatus.AVAILABLE.value,
            message=(
                "승인된 GET/HEAD 1회를 전송하고 원본 응답과 구조를 비교했습니다."
                + (" 응답은 크기 제한으로 잘렸습니다." if truncated else "")
            ),
            comparison=comparison,
            synthetic=False,
        )
        return execution, {
            "hostname": destination.hostname,
            "resolved_addresses": list(destination.addresses),
            "response_status": response_status,
            "response_headers": response_headers,
            "response_body": response_body,
            "response_truncated": truncated,
        }
