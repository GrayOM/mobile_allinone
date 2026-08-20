from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable
from urllib.parse import urlsplit

from backend.app.core.status import RunMode


MAX_ALLOWED_NETWORK_HOSTS = 50
MAX_AUTHORIZATION_WINDOW = timedelta(days=366)
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class ControlScopeError(ValueError):
    """Raised when an approved control-validation boundary is invalid."""


def _required_text(
    raw: dict[str, Any],
    field: str,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> str:
    value = raw.get(field)
    if not isinstance(value, str) or not minimum <= len(value.strip()) <= maximum:
        raise ControlScopeError(f"{label}은 {minimum}~{maximum}자로 입력하세요.")
    return value.strip()


def normalize_network_host(value: str) -> str:
    candidate = value.strip().lower().rstrip(".")
    if not candidate:
        raise ControlScopeError("허용 서버 호스트에는 빈 값을 사용할 수 없습니다.")
    if "://" in candidate or any(token in candidate for token in ("/", "?", "#", "@")):
        raise ControlScopeError(
            "허용 서버는 URL이 아니라 호스트 또는 *.example.test 형식으로 입력하세요."
        )

    wildcard = candidate.startswith("*.")
    host = candidate[2:] if wildcard else candidate
    if not host or "*" in host:
        raise ControlScopeError("와일드카드는 호스트 맨 앞의 *. 형식만 허용됩니다.")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ControlScopeError("허용 서버 호스트 형식이 올바르지 않습니다.") from exc
        labels = host.split(".")
        if (
            len(host) > 253
            or any(not label or not _HOST_LABEL.fullmatch(label) for label in labels)
            or (wildcard and len(labels) < 2)
        ):
            raise ControlScopeError("허용 서버 호스트 형식이 올바르지 않습니다.")
    else:
        if wildcard:
            raise ControlScopeError("IP 주소에는 와일드카드를 사용할 수 없습니다.")
        host = address.compressed
    return f"*.{host}" if wildcard else host


def normalize_network_hosts(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ControlScopeError("통제 검증에는 허용 테스트 서버를 1개 이상 입력하세요.")
    if len(value) > MAX_ALLOWED_NETWORK_HOSTS:
        raise ControlScopeError(
            f"허용 테스트 서버는 최대 {MAX_ALLOWED_NETWORK_HOSTS}개까지 입력할 수 있습니다."
        )
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ControlScopeError("허용 테스트 서버는 문자열 배열이어야 합니다.")
        host = normalize_network_host(item)
        if host not in normalized:
            normalized.append(host)
    return normalized


def _parse_authorization_expiry(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ControlScopeError("승인 만료 시각은 시간대가 포함된 ISO-8601 값이어야 합니다.")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ControlScopeError(
            "승인 만료 시각은 시간대가 포함된 ISO-8601 값이어야 합니다."
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ControlScopeError("승인 만료 시각에는 시간대 정보가 필요합니다.")
    return parsed.astimezone(timezone.utc)


def normalize_control_validation_request(
    raw: dict[str, Any],
    run_mode: RunMode,
    selected_device_id: str,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    if run_mode != RunMode.LIVE:
        raise ControlScopeError("통제 검증 모드는 실제 Live 진단에서만 사용할 수 있습니다.")

    acknowledgement_fields = {
        "authorized_scope_confirmed": "명시적 진단 권한 확인",
        "test_environment_confirmed": "테스트 환경 확인",
        "test_data_only_confirmed": "테스트 계정·데이터 확인",
    }
    for field, label in acknowledgement_fields.items():
        if raw.get(field) is not True:
            raise ControlScopeError(f"통제 검증에는 {label} 동의가 필요합니다.")

    authorized_device_id = _required_text(
        raw,
        "authorized_device_id",
        "승인된 테스트 단말 식별값",
        minimum=1,
        maximum=255,
    )
    if authorized_device_id != selected_device_id:
        raise ControlScopeError(
            "승인된 테스트 단말과 현재 선택한 단말이 다릅니다. 승인 범위를 다시 확인하세요."
        )

    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires_at = _parse_authorization_expiry(raw.get("authorization_expires_at"))
    if expires_at <= current:
        raise ControlScopeError("승인 기간이 만료되었습니다. 새 승인 범위를 입력하세요.")
    if expires_at - current > MAX_AUTHORIZATION_WINDOW:
        raise ControlScopeError("승인 기간은 현재 시각부터 최대 366일까지 설정할 수 있습니다.")

    return {
        "enabled": True,
        "mode": "authorized_control_validation",
        "execution_policy": "observation_plus_approved_manual_bypass",
        "automatic_control_evasion": False,
        "external_ai_excluded": True,
        "network_scope_policy": "default_deny",
        "out_of_scope_action": "stop_and_manual_review",
        "authorization_reference": _required_text(
            raw,
            "authorization_reference",
            "승인 참조 값",
            minimum=4,
            maximum=200,
        ),
        "approved_by": _required_text(
            raw,
            "approved_by",
            "승인자 또는 승인 기관",
            minimum=2,
            maximum=120,
        ),
        "scope_description": _required_text(
            raw,
            "scope_description",
            "승인된 테스트 범위",
            minimum=10,
            maximum=1000,
        ),
        "test_account_reference": _required_text(
            raw,
            "test_account_reference",
            "테스트 계정 참조",
            minimum=2,
            maximum=200,
        ),
        "authorized_device_id": selected_device_id,
        "allowed_network_hosts": normalize_network_hosts(
            raw.get("allowed_network_hosts")
        ),
        "authorization_expires_at": expires_at.isoformat(),
        "authorized_scope_confirmed": True,
        "test_environment_confirmed": True,
        "test_data_only_confirmed": True,
        "consent_recorded_at": current.isoformat(),
    }


def active_control_scope(
    options: dict[str, Any],
    device_id: str,
    *,
    now: datetime | None = None,
) -> dict[str, Any] | None:
    raw = options.get("control_validation")
    if not isinstance(raw, dict) or raw.get("enabled") is not True:
        return None
    if raw.get("authorized_device_id") != device_id:
        raise ControlScopeError(
            "승인 범위에 기록된 단말과 실행 단말이 달라 자동 진단을 중단했습니다."
        )
    expires_at = _parse_authorization_expiry(raw.get("authorization_expires_at"))
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if expires_at <= current:
        raise ControlScopeError("승인 기간이 만료되어 자동 진단을 중단했습니다.")
    normalize_network_hosts(raw.get("allowed_network_hosts"))
    return raw


def network_host_allowed(host: str | None, allowed_hosts: Iterable[str]) -> bool:
    if not host:
        return False
    try:
        candidate = normalize_network_host(host)
    except ControlScopeError:
        return False
    for rule in allowed_hosts:
        if rule.startswith("*."):
            suffix = rule[1:]
            if candidate.endswith(suffix) and candidate != rule[2:]:
                return True
        elif candidate == rule:
            return True
    return False


def evaluate_network_scope(
    flows: Iterable[Any],
    flow_ids: Iterable[str],
    allowed_hosts: list[str],
) -> dict[str, Any]:
    violations: list[dict[str, Any]] = []
    flow_count = 0
    in_scope_count = 0
    for flow, flow_id in zip(flows, flow_ids):
        flow_count += 1
        try:
            parsed = urlsplit(str(getattr(flow, "url", "")))
            host = parsed.hostname
            port = parsed.port
        except ValueError:
            parsed = urlsplit("")
            host = None
            port = None
        if parsed.scheme in {"http", "https"} and host and network_host_allowed(
            host, allowed_hosts
        ):
            in_scope_count += 1
            continue
        response_headers = getattr(flow, "response_headers", {}) or {}
        blocked = any(
            str(key).lower() == "x-msw-control-scope"
            and str(value).lower() == "blocked"
            for key, value in response_headers.items()
        )
        origin = "invalid-url"
        if parsed.scheme in {"http", "https"} and host:
            default_port = 443 if parsed.scheme == "https" else 80
            port_text = f":{port}" if port and port != default_port else ""
            display_host = f"[{host}]" if ":" in host else host
            origin = f"{parsed.scheme}://{display_host}{port_text}"
        violations.append(
            {
                "source_flow_id": flow_id,
                "method": str(getattr(flow, "method", "GET")).upper(),
                "origin": origin,
                "blocked_before_upstream": blocked,
            }
        )
    return {
        "status": "violation" if violations else ("within_scope" if flow_count else "no_traffic"),
        "policy": "default_deny",
        "allowed_network_hosts": list(allowed_hosts),
        "evaluated_flow_count": flow_count,
        "in_scope_count": in_scope_count,
        "violation_count": len(violations),
        "violations": violations,
        "automatic_execution_stopped": bool(violations),
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }
