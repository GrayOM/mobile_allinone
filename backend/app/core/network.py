from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import SplitResult, urlsplit, urlunsplit

import httpcore
import httpx
from httpcore._backends.auto import AutoBackend

from backend.app.core.config import AppSettings


@dataclass(frozen=True, slots=True)
class DestinationSnapshot:
    base_url: str
    origin: str
    addresses: tuple[str, ...]
    certificate_sha256: str | None


class _PinnedNetworkStream(httpcore.AsyncNetworkStream):
    def __init__(
        self,
        stream: httpcore.AsyncNetworkStream,
        *,
        hostname: str,
        certificate_sha256: str | None,
    ):
        self._stream = stream
        self._hostname = hostname
        self._certificate_sha256 = certificate_sha256

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return await self._stream.read(max_bytes, timeout)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        await self._stream.write(buffer, timeout)

    async def aclose(self) -> None:
        await self._stream.aclose()

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        if (server_hostname or "").rstrip(".").lower() != self._hostname:
            await self.aclose()
            raise httpcore.ConnectError("MobSF TLS SNI가 승인된 hostname과 다릅니다.")
        secured = await self._stream.start_tls(
            ssl_context,
            server_hostname=server_hostname,
            timeout=timeout,
        )
        ssl_object = secured.get_extra_info("ssl_object")
        certificate = ssl_object.getpeercert(binary_form=True) if ssl_object else None
        actual_fingerprint = hashlib.sha256(certificate).hexdigest() if certificate else None
        if actual_fingerprint != self._certificate_sha256:
            await secured.aclose()
            raise httpcore.ConnectError("MobSF TLS 인증서가 승인 Snapshot과 다릅니다.")
        return _PinnedNetworkStream(
            secured,
            hostname=self._hostname,
            certificate_sha256=self._certificate_sha256,
        )

    def get_extra_info(self, info: str) -> Any:
        return self._stream.get_extra_info(info)


class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Resolve no DNS during HTTP transfer; connect only to approved addresses."""

    def __init__(self, snapshot: DestinationSnapshot):
        parsed = urlsplit(snapshot.base_url)
        self.hostname = str(parsed.hostname or "").rstrip(".").lower()
        self.addresses = snapshot.addresses
        self.certificate_sha256 = snapshot.certificate_sha256
        self._backend = AutoBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[tuple[int, int, int | bytes]] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        if host.rstrip(".").lower() != self.hostname:
            raise httpcore.ConnectError("MobSF 요청 hostname이 승인 Snapshot과 다릅니다.")
        failures: list[str] = []
        for address in self.addresses:
            try:
                stream = await self._backend.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
                peer = stream.get_extra_info("server_addr")
                peer_address = str(ipaddress.ip_address(peer[0])) if peer else ""
                if peer_address != str(ipaddress.ip_address(address)):
                    await stream.aclose()
                    raise httpcore.ConnectError(
                        "MobSF 실제 peer IP가 승인된 연결 IP와 다릅니다."
                    )
                return _PinnedNetworkStream(
                    stream,
                    hostname=self.hostname,
                    certificate_sha256=self.certificate_sha256,
                )
            except Exception as exc:
                failures.append(f"{address}: {type(exc).__name__}: {exc}")
        raise httpcore.ConnectError(
            "승인된 MobSF IP로 연결하지 못했습니다: " + "; ".join(failures)
        )

    async def connect_unix_socket(self, *args: Any, **kwargs: Any):
        raise httpcore.ConnectError("MobSF는 Unix socket 연결을 사용하지 않습니다.")

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


class PinnedAsyncHTTPTransport(httpx.AsyncHTTPTransport):
    def __init__(self, snapshot: DestinationSnapshot):
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl.create_default_context(),
            retries=0,
            network_backend=PinnedNetworkBackend(snapshot),
        )


def pinned_http_transport(snapshot: DestinationSnapshot) -> httpx.AsyncHTTPTransport:
    return PinnedAsyncHTTPTransport(snapshot)


def _parsed_destination(settings: AppSettings) -> tuple[SplitResult | None, str | None]:
    raw_url = str(settings.mobsf_url or "").strip()
    try:
        parsed = urlsplit(raw_url)
    except ValueError as exc:
        return None, f"MobSF URL 해석 실패: {exc}"
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None, "MobSF URL은 http/https와 명시적인 호스트를 사용해야 합니다."
    if parsed.username or parsed.password:
        return None, "MobSF URL에 사용자명이나 비밀번호를 포함할 수 없습니다."
    if parsed.query or parsed.fragment:
        return None, "MobSF URL에는 Query String이나 Fragment를 포함할 수 없습니다."
    return parsed, None


def _allowed_networks(
    settings: AppSettings,
) -> tuple[list[ipaddress.IPv4Network | ipaddress.IPv6Network], str | None]:
    try:
        return [
            ipaddress.ip_network(value, strict=False)
            for value in settings.mobsf_allowed_networks
        ], None
    except ValueError as exc:
        return [], f"MobSF 허용 네트워크 설정이 올바르지 않습니다: {exc}"


def validate_mobsf_destination(settings: AppSettings) -> tuple[bool, str]:
    parsed, error = _parsed_destination(settings)
    if not parsed:
        return False, str(error)
    networks, error = _allowed_networks(settings)
    if error:
        return False, error
    host = str(parsed.hostname).rstrip(".").lower()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        allowed_hosts = {
            item.rstrip(".").lower() for item in settings.mobsf_allowed_hosts
        }
        if host != "localhost" and host not in allowed_hosts:
            return False, "MobSF hostname은 MSW_MOBSF_ALLOWED_HOSTS에 명시해야 합니다."
        return True, "허용 hostname이며 전송 전 모든 DNS 주소를 추가 검증합니다."
    if not any(address in network for network in networks):
        return False, f"MobSF 주소 {address}가 허용 네트워크에 포함되지 않습니다."
    return True, "허용 네트워크의 MobSF 주소입니다."


async def inspect_mobsf_destination(settings: AppSettings) -> DestinationSnapshot:
    allowed, message = validate_mobsf_destination(settings)
    if not allowed:
        raise ValueError(message)
    parsed, error = _parsed_destination(settings)
    if not parsed:
        raise ValueError(str(error))
    networks, error = _allowed_networks(settings)
    if error:
        raise ValueError(error)
    host = str(parsed.hostname).rstrip(".").lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    loop = asyncio.get_running_loop()
    try:
        records = await asyncio.wait_for(
            loop.getaddrinfo(
                host,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            ),
            timeout=5,
        )
    except (OSError, asyncio.TimeoutError) as exc:
        raise ValueError(f"MobSF DNS 해석 실패: {exc}") from exc
    addresses = tuple(
        sorted({str(ipaddress.ip_address(record[4][0])) for record in records})
    )
    if not addresses:
        raise ValueError("MobSF hostname에서 A/AAAA 주소를 확인할 수 없습니다.")
    disallowed = [
        value
        for value in addresses
        if not any(ipaddress.ip_address(value) in network for network in networks)
    ]
    if disallowed:
        raise ValueError(
            "MobSF hostname의 모든 A/AAAA 주소가 허용 네트워크에 포함되어야 합니다: "
            + ", ".join(disallowed)
        )

    certificate_sha256 = None
    if parsed.scheme == "https":
        context = ssl.create_default_context()
        failures: list[str] = []
        for address in addresses:
            writer: asyncio.StreamWriter | None = None
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        address,
                        port,
                        ssl=context,
                        server_hostname=host,
                    ),
                    timeout=8,
                )
                del reader
                peer = writer.get_extra_info("peername")
                if not peer or str(ipaddress.ip_address(peer[0])) != address:
                    raise ValueError("MobSF 실제 peer IP가 검증 대상 IP와 다릅니다.")
                ssl_object = writer.get_extra_info("ssl_object")
                certificate = ssl_object.getpeercert(binary_form=True) if ssl_object else None
                if not certificate:
                    raise ValueError("MobSF TLS 인증서를 읽을 수 없습니다.")
                certificate_sha256 = hashlib.sha256(certificate).hexdigest()
                break
            except (OSError, ssl.SSLError, asyncio.TimeoutError, ValueError) as exc:
                failures.append(f"{address}: {type(exc).__name__}: {exc}")
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except (OSError, ssl.SSLError):
                        pass
        if not certificate_sha256:
            raise ValueError("MobSF TLS 인증서 검증 실패: " + "; ".join(failures))

    default_port = 443 if parsed.scheme == "https" else 80
    host_display = f"[{host}]" if ":" in host else host
    netloc = host_display if port == default_port else f"{host_display}:{port}"
    path = parsed.path.rstrip("/")
    base_url = urlunsplit((parsed.scheme, netloc, path, "", ""))
    origin = urlunsplit((parsed.scheme, netloc, "", "", ""))
    return DestinationSnapshot(
        base_url=base_url,
        origin=origin,
        addresses=addresses,
        certificate_sha256=certificate_sha256,
    )


def approval_matches_destination(
    snapshot: DestinationSnapshot,
    *,
    approved_destination: str | None,
    approved_addresses: list[str] | None,
    approved_certificate_sha256: str | None,
) -> bool:
    return (
        snapshot.base_url == (approved_destination or "")
        and snapshot.addresses == tuple(sorted(approved_addresses or []))
        and snapshot.certificate_sha256 == approved_certificate_sha256
    )
