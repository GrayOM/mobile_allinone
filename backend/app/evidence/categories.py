from __future__ import annotations

import re
from enum import Enum


class CanonicalFindingCategory(str, Enum):
    AUTHORIZATION = "authorization"
    LOCAL_STORAGE = "local_storage"
    NETWORK_SENSITIVE_EXPOSURE = "network_sensitive_exposure"
    RUNTIME_LOG_EXPOSURE = "runtime_log_exposure"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    FRIDA_CONTROL = "frida_control"
    NAVIGATION = "navigation"


def _key(value: str) -> str:
    return re.sub(
        r"_+", "_", re.sub(r"[^\w가-힣]+", "_", value.casefold())
    ).strip("_")


CATEGORY_ALIASES: dict[str, CanonicalFindingCategory] = {
    alias: category
    for category, aliases in {
        CanonicalFindingCategory.AUTHORIZATION: {
            "idor",
            "authorization",
            "authorization_boundary",
            "access_control",
            "object_boundary",
        },
        CanonicalFindingCategory.LOCAL_STORAGE: {
            "local_storage",
            "local_data",
            "shared_preferences",
            "sqlite",
            "insecure_data_storage",
        },
        CanonicalFindingCategory.NETWORK_SENSITIVE_EXPOSURE: {
            "network_sensitive_exposure",
            "api_sensitive_exposure",
        },
        CanonicalFindingCategory.RUNTIME_LOG_EXPOSURE: {
            "runtime_log_exposure",
            "log_sensitive_exposure",
        },
        CanonicalFindingCategory.SENSITIVE_DATA_EXPOSURE: {
            "sensitive_data_exposure",
        },
        CanonicalFindingCategory.FRIDA_CONTROL: {
            "frida",
            "hook",
            "root_detection",
            "certificate_pinning",
            "anti_tamper",
            "anti_frida",
        },
        CanonicalFindingCategory.NAVIGATION: {
            "navigation",
            "deep_link",
            "exported_component",
        },
    }.items()
    for alias in aliases
}


def normalize_finding_category(
    value: str,
) -> CanonicalFindingCategory | None:
    """Map an AI/user label through exact aliases; never infer by substring."""

    return CATEGORY_ALIASES.get(_key(value))
