from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass

from backend.app.core.targets import is_valid_host


_BRACKETED_ENDPOINT = re.compile(r"^\[([^\]]+)]:(\d{1,5})$")


def normalize_frida_endpoint(value: str) -> tuple[str, str, int]:
    endpoint = value.strip()
    if (
        not endpoint
        or "://" in endpoint
        or any(marker in endpoint for marker in ("/", "?", "#", "@"))
        or any(character.isspace() for character in endpoint)
    ):
        raise ValueError("Frida endpoint는 host:port 형식이어야 합니다.")

    bracketed = _BRACKETED_ENDPOINT.fullmatch(endpoint)
    if bracketed:
        host, port_text = bracketed.groups()
    else:
        host, separator, port_text = endpoint.rpartition(":")
        if not separator or not host or ":" in host:
            raise ValueError(
                "Frida endpoint는 host:port 또는 [IPv6]:port 형식이어야 합니다."
            )
    host = host.strip().rstrip(".")
    if not is_valid_host(host):
        raise ValueError("Frida endpoint host 형식이 올바르지 않습니다.")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ValueError("Frida endpoint port 형식이 올바르지 않습니다.") from exc
    if not 1 <= port <= 65535:
        raise ValueError("Frida endpoint port 범위가 올바르지 않습니다.")

    try:
        parsed = ipaddress.ip_address(host)
        normalized_host = parsed.compressed
        normalized = (
            f"[{normalized_host}]:{port}"
            if parsed.version == 6
            else f"{normalized_host}:{port}"
        )
    except ValueError:
        normalized_host = host.lower()
        normalized = f"{normalized_host}:{port}"
    return normalized, normalized_host, port


@dataclass(frozen=True, slots=True)
class FridaTarget:
    transport: str
    device_id: str | None = None
    endpoint: str | None = None
    host: str | None = None
    port: int | None = None

    @classmethod
    def usb(cls, device_id: str) -> "FridaTarget":
        normalized = device_id.strip()
        if not normalized:
            raise ValueError("USB Frida 대상에는 단말 ID가 필요합니다.")
        return cls(transport="usb", device_id=normalized)

    @classmethod
    def remote(cls, endpoint: str) -> "FridaTarget":
        normalized, host, port = normalize_frida_endpoint(endpoint)
        return cls(
            transport="remote",
            endpoint=normalized,
            host=host,
            port=port,
        )

    @property
    def display(self) -> str:
        return str(self.endpoint or self.device_id or "")

    @property
    def command_option(self) -> str:
        return "-H" if self.transport == "remote" else "-D"

    def to_dict(self) -> dict[str, str | int | None]:
        return asdict(self)
