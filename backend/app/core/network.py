from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from backend.app.core.config import AppSettings


def validate_mobsf_destination(settings: AppSettings) -> tuple[bool, str]:
    raw_url = str(settings.mobsf_url or "").strip()
    try:
        parsed = urlsplit(raw_url)
    except ValueError as exc:
        return False, f"MobSF URL 해석 실패: {exc}"
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False, "MobSF URL은 http/https와 명시적인 호스트를 사용해야 합니다."
    if parsed.username or parsed.password:
        return False, "MobSF URL에 사용자명이나 비밀번호를 포함할 수 없습니다."
    host = parsed.hostname.rstrip(".").lower()
    if host in {item.rstrip(".").lower() for item in settings.mobsf_allowed_hosts}:
        return True, "명시적으로 허용된 MobSF hostname입니다."
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if host != "localhost":
            return False, "MobSF hostname은 MSW_MOBSF_ALLOWED_HOSTS에 명시해야 합니다."
        address = ipaddress.ip_address("127.0.0.1")
    try:
        networks = [
            ipaddress.ip_network(value, strict=False)
            for value in settings.mobsf_allowed_networks
        ]
    except ValueError as exc:
        return False, f"MobSF 허용 네트워크 설정이 올바르지 않습니다: {exc}"
    if not any(address in network for network in networks):
        return False, f"MobSF 주소 {address}가 허용 네트워크에 포함되지 않습니다."
    return True, "허용 네트워크의 MobSF 주소입니다."
