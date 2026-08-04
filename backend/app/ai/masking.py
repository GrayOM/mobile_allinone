from __future__ import annotations

import json
import math
import re
from collections import Counter
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


DEFAULT_SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "setcookie",
    "xapikey",
    "apikey",
    "password",
    "passwd",
    "passcode",
    "pin",
    "secret",
    "clientsecret",
    "token",
    "accesstoken",
    "refreshtoken",
    "session",
    "sessionid",
    "jsessionid",
    "deviceid",
    "advertisingid",
    "residentnumber",
    "registrationnumber",
    "ssn",
}

JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
PHONE = re.compile(r"(?<!\d)(?:\+?82[- ]?)?0?1[016789][ -]?\d{3,4}[ -]?\d{4}(?!\d)")
KOREAN_ID = re.compile(r"(?<!\d)\d{6}[- ]?[1-8]\d{6}(?!\d)")
URL = re.compile(r"https?://[^\s\"'<>]+", re.I)
NAMED_SECRET = re.compile(
    r"(?i)(authorization|cookie|set-cookie|x-api-key|api[_-]?key|password|passwd|"
    r"session[_-]?id|device[_-]?id|secret|access[_-]?token|refresh[_-]?token)"
    r"([\"']?\s*[:=]\s*[\"']?)([^,\"'\s}]+)"
)
TOKENISH = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_+/=-]{20,}(?![A-Za-z0-9])")


def _normalize_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def _mask_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        path_parts = []
        for part in parsed.path.split("/"):
            if EMAIL.search(part) or PHONE.search(part) or KOREAN_ID.search(part):
                path_parts.append("[MASKED_PATH]")
            elif len(part) >= 20 and _entropy(part) >= 3.8:
                path_parts.append("[MASKED_PATH]")
            else:
                path_parts.append(part)
        query = urlencode([(key, "[MASKED_QUERY]") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)])
        host = "[MASKED_DOMAIN]"
        if parsed.port:
            host += f":{parsed.port}"
        return urlunsplit((parsed.scheme, host, "/".join(path_parts), query, ""))
    except (TypeError, ValueError):
        return "[MASKED_URL]"


def mask_text(value: str) -> tuple[str, list[str]]:
    applied: list[str] = []

    def replace(pattern: re.Pattern[str], replacement: str, name: str, text: str) -> str:
        masked, count = pattern.subn(replacement, text)
        if count:
            applied.append(f"{name}:{count}")
        return masked

    value = replace(NAMED_SECRET, r"\1\2[MASKED_SECRET]", "named_secret", value)
    value = replace(JWT, "[MASKED_JWT]", "jwt", value)
    value = replace(EMAIL, "[MASKED_EMAIL]", "email", value)
    value = replace(PHONE, "[MASKED_PHONE]", "phone", value)
    value = replace(KOREAN_ID, "[MASKED_RESIDENT_NUMBER]", "resident_number", value)
    value, url_count = URL.subn(lambda match: _mask_url(match.group(0)), value)
    if url_count:
        applied.append(f"url:{url_count}")

    def token_replacement(match: re.Match[str]) -> str:
        token = match.group(0)
        if _entropy(token) >= 4.0 and not token.startswith("MASKED_"):
            applied.append("high_entropy:1")
            return "[MASKED_HIGH_ENTROPY]"
        return token

    value = TOKENISH.sub(token_replacement, value)
    return value, applied


def _sanitize(value: Any, sensitive_keys: set[str], applied: list[str], key: str | None = None) -> Any:
    if key is not None and _normalize_key(key) in sensitive_keys:
        applied.append(f"key:{key}")
        return "[MASKED_FIELD]"
    if isinstance(value, dict):
        return {
            str(child_key): _sanitize(child, sensitive_keys, applied, str(child_key))
            for child_key, child in value.items()
        }
    if isinstance(value, list):
        return [_sanitize(child, sensitive_keys, applied) for child in value]
    if isinstance(value, tuple):
        return [_sanitize(child, sensitive_keys, applied) for child in value]
    if isinstance(value, str):
        masked, text_rules = mask_text(value)
        applied.extend(text_rules)
        return masked
    return value


def mask_context(
    context: dict[str, Any], custom_keys: Iterable[str] | None = None
) -> tuple[str, list[str]]:
    keys = set(DEFAULT_SENSITIVE_KEYS)
    keys.update(_normalize_key(item) for item in (custom_keys or []))
    applied: list[str] = []
    sanitized = _sanitize(context, keys, applied)
    return json.dumps(sanitized, ensure_ascii=False, default=str), applied
