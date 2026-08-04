from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit, urlunsplit

from backend.app.core.config import AppSettings


@dataclass(frozen=True, slots=True)
class DestinationSnapshot:
    base_url: str
    origin: str
    addresses: tuple[str, ...]
    certificate_sha256: str | None


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
        writer: asyncio.StreamWriter | None = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host,
                    port,
                    ssl=context,
                    server_hostname=host,
                ),
                timeout=8,
            )
            del reader
            ssl_object = writer.get_extra_info("ssl_object")
            certificate = ssl_object.getpeercert(binary_form=True) if ssl_object else None
            if not certificate:
                raise ValueError("MobSF TLS 인증서를 읽을 수 없습니다.")
            certificate_sha256 = hashlib.sha256(certificate).hexdigest()
        except (OSError, ssl.SSLError, asyncio.TimeoutError) as exc:
            raise ValueError(f"MobSF TLS 인증서 검증 실패: {exc}") from exc
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, ssl.SSLError):
                    pass

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
