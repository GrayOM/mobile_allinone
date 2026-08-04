from __future__ import annotations

import ipaddress
import re


ANDROID_PACKAGE_PATTERN = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$"
)
IOS_BUNDLE_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*)+$"
)
SSH_USERNAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")
HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


def normalize_platform(value: str) -> str:
    lowered = value.strip().lower()
    if lowered in {"android", "mock_android"}:
        return "android"
    if lowered in {"ios", "mock_ios"}:
        return "ios"
    raise ValueError(f"지원하지 않는 앱 플랫폼입니다: {value}")


def platform_for_adapter(adapter: str, device_id: str = "") -> str:
    if adapter == "android_adb":
        return "android"
    if adapter == "ios_windows":
        return "ios"
    if adapter == "mock":
        return "ios" if "ios" in device_id.lower() else "android"
    raise ValueError(f"지원하지 않는 단말 Adapter입니다: {adapter}")


def is_valid_app_identifier(platform: str, value: str | None) -> bool:
    if not value:
        return False
    normalized = normalize_platform(platform)
    pattern = ANDROID_PACKAGE_PATTERN if normalized == "android" else IOS_BUNDLE_PATTERN
    return bool(pattern.fullmatch(value))


def require_app_identifier(platform: str, value: str | None) -> str:
    if not is_valid_app_identifier(platform, value):
        label = (
            "Android 패키지명"
            if normalize_platform(platform) == "android"
            else "iOS Bundle ID"
        )
        raise ValueError(f"{label} 형식이 올바르지 않거나 식별자를 추출하지 못했습니다.")
    return str(value)


def is_valid_host(value: str) -> bool:
    host = value.strip().rstrip(".")
    if not host or any(character.isspace() for character in host):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOSTNAME_PATTERN.fullmatch(host))


def is_loopback_host(value: str) -> bool:
    host = value.strip().strip("[]").rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
