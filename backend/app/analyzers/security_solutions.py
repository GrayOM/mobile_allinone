"""Static fingerprinting for mobile app-protection and security SDKs.

The scanner identifies integration evidence and explains why a product was
selected. It never claims that a control is enabled, effective, or bypassable;
those decisions require an approved live-device verification.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable


CATALOG_VERSION = "2026.10.15.2"


@dataclass(frozen=True, slots=True)
class SolutionIndicator:
    value: str
    kind: str
    weight: float


@dataclass(frozen=True, slots=True)
class SolutionSignature:
    signature_id: str
    vendor: str
    product: str
    category: str
    platforms: tuple[str, ...]
    indicators: tuple[SolutionIndicator, ...]


def _ind(value: str, kind: str = "product_marker", weight: float = 0.18) -> SolutionIndicator:
    return SolutionIndicator(value, kind, weight)


def _sig(
    signature_id: str,
    vendor: str,
    product: str,
    category: str,
    platforms: tuple[str, ...],
    *,
    packages: tuple[str, ...] = (),
    libraries: tuple[str, ...] = (),
    frameworks: tuple[str, ...] = (),
    markers: tuple[str, ...] = (),
) -> SolutionSignature:
    raw_indicators = (
        tuple(_ind(value, "package", 0.42) for value in packages)
        + tuple(_ind(value, "native_library", 0.48) for value in libraries)
        + tuple(_ind(value, "framework", 0.5) for value in frameworks)
        + tuple(_ind(value) for value in markers)
    )
    seen: set[tuple[str, str]] = set()
    indicators: list[SolutionIndicator] = []
    for indicator in raw_indicators:
        key = (indicator.value.casefold(), indicator.kind)
        if key not in seen:
            indicators.append(indicator)
            seen.add(key)
    return SolutionSignature(
        signature_id,
        vendor,
        product,
        category,
        platforms,
        tuple(indicators),
    )


# Only stable integration fingerprints belong here. Generic security words are
# deliberately excluded because they produce misleading vendor attribution.
SIGNATURES: tuple[SolutionSignature, ...] = (
    _sig("inka-appsealing", "INKA Entworks", "AppSealing", "app_shield", ("android", "ios"), packages=("com.inka.appsealing",), libraries=("libcovault",), markers=("AppSealing", "appsealing")),
    _sig("lockin-liapp", "Lockin Company", "LIAPP", "app_shield", ("android", "ios"), packages=("com.lockincomp",), libraries=("libliapp",), markers=("LIAPP", "liapp")),
    _sig("licel-dexprotector", "Licel", "DexProtector", "obfuscator", ("android", "ios"), packages=("com.licel",), markers=("DexProtector", "dexprotector")),
    _sig("guardsquare-dexguard", "Guardsquare", "DexGuard", "obfuscator", ("android",), markers=("DexGuard", "dexguard")),
    _sig("guardsquare-ixguard", "Guardsquare", "iXGuard", "obfuscator", ("ios",), markers=("iXGuard", "ixguard")),
    _sig("promon-shield", "Promon", "SHIELD", "app_shield", ("android", "ios"), packages=("no.promon.shield",), libraries=("libshield",), markers=("Promon", "promon")),
    _sig("digitalai-app-protection", "Digital.ai (Arxan)", "App Protection", "app_shield", ("android", "ios"), packages=("com.arxan",), libraries=("libarxan",), markers=("Arxan", "arxan", "digital.ai")),
    _sig("appdome", "Appdome", "Appdome", "app_shield", ("android", "ios"), markers=("Appdome", "appdome")),
    _sig("zimperium-ziap", "Zimperium", "zIAP / zDefend", "mobile_threat_defense", ("android", "ios"), packages=("com.zimperium",), markers=("Zimperium", "zimperium", "zDefend", "zIAP")),
    _sig("verimatrix-app-shield", "Verimatrix", "XTD / App Shield", "app_shield", ("android", "ios"), packages=("com.insidesecure",), markers=("Verimatrix", "verimatrix")),
    _sig("ahnlab-v3-mobile-plus", "AhnLab", "V3 Mobile Plus", "anti_malware", ("android",), packages=("com.ahnlab.v3mobileplus",), markers=("V3MobilePlus", "v3mobileplus")),
    _sig("inca-nprotect-appguard", "Inca Internet", "nProtect AppGuard", "app_shield", ("android", "ios"), packages=("com.nprotect",), markers=("nProtect", "nprotect")),
    _sig("raonsecure-mtranskey", "RaonSecure", "TouchEn mTransKey", "secure_keypad", ("android", "ios"), packages=("com.raon",), markers=("TouchEn", "mTransKey", "mtranskey")),
    _sig("secure-keypad-etc", "Softcamp / Secuve", "Secure keypad (ETC)", "secure_keypad", ("android", "ios"), packages=("com.softforum", "com.secuve"), markers=("SecureKeypad", "securekeypad")),
    _sig("stealien-appsuit", "STEALIEN", "AppSuit", "app_shield", ("android", "ios"), packages=("com.stealien",), libraries=("libappsuit",), markers=("AppSuit", "stealien")),
    _sig("everspin-eversafe", "Everspin", "EverSafe", "anti_malware", ("android", "ios"), packages=("com.everspin",), markers=("EverSafe", "everspin")),
    _sig("sk-droidx", "SK Infosec / Unify", "DroidX", "app_shield", ("android",), libraries=("libdroidx",), markers=("DroidX", "droidx")),
    _sig("bangcle", "Bangcle / SecNeo", "Bangcle", "app_shield", ("android",), packages=("com.secneo",), libraries=("libsecexe", "libsecmain"), markers=("Bangcle", "bangcle")),
    _sig("tencent-legu", "Tencent", "Legu", "app_shield", ("android",), packages=("com.tencent.legu",), libraries=("libshella", "libshellx"), markers=("Legu",)),
    _sig("qihoo-jiagu", "Qihoo 360", "Jiagu", "app_shield", ("android",), packages=("com.qihoo.util",), libraries=("libjiagu",), markers=("Jiagu", "jiagu")),
    _sig("nshc-appguard", "NHN Cloud / NSHC", "AppGuard (NSHC)", "app_shield", ("android", "ios"), packages=("com.nshc",), markers=("NSHC", "nshc")),
    _sig("talsec-freerasp", "Talsec", "freeRASP", "app_shield", ("android", "ios"), packages=("com.aheaditec.talsec.security", "app.talsec.rasp"), frameworks=("TalsecRuntime.framework",), markers=("freeRASP", "TalsecSecurity")),
    _sig("google-play-integrity", "Google", "Play Integrity API", "platform_attestation", ("android",), packages=("com.google.android.play.core.integrity",), markers=("StandardIntegrityManager", "IntegrityManagerFactory")),
    _sig("apple-app-attest", "Apple", "App Attest / DeviceCheck", "platform_attestation", ("ios",), frameworks=("DeviceCheck.framework",), markers=("DCAppAttestService", "DCDevice")),
    _sig("firebase-app-check", "Google Firebase", "Firebase App Check", "platform_attestation", ("android", "ios"), packages=("com.google.firebase.appcheck",), frameworks=("FirebaseAppCheck.framework",), markers=("FIRAppCheck",)),
)

_CATEGORY_LABELS = {
    "app_shield": "앱 무결성·안티탬퍼(RASP)",
    "obfuscator": "난독화·코드 보호",
    "secure_keypad": "보안 키패드",
    "anti_malware": "안티바이러스·악성앱 탐지",
    "mobile_threat_defense": "모바일 위협 탐지",
    "platform_attestation": "앱·단말 무결성 증명",
}

_EXPECTED_CONTROLS = {
    "app_shield": ["tamper_detection", "root_jailbreak_detection", "hook_debug_detection"],
    "obfuscator": ["code_obfuscation", "reverse_engineering_resistance"],
    "secure_keypad": ["sensitive_input_protection", "screen_input_isolation"],
    "anti_malware": ["malicious_app_detection", "device_risk_response"],
    "mobile_threat_defense": ["runtime_threat_detection", "device_risk_telemetry"],
    "platform_attestation": ["app_integrity_attestation", "device_integrity_attestation"],
}

_KIND_LABELS = {
    "package": "패키지·클래스",
    "native_library": "네이티브 라이브러리",
    "framework": "프레임워크",
    "product_marker": "제품 문자열",
    "control_signal": "보호 동작 신호",
}

_CUSTOM_PROTECTION_SIGNATURE = SolutionSignature(
    "custom-in-app-protection",
    "Vendor not identified",
    "Custom / in-app protection logic",
    "app_shield",
    ("android", "ios"),
    (),
)

_CUSTOM_CONTROL_GROUPS = (
    "root_jailbreak_detection",
    "frida_hook_detection",
    "debugger_detection",
    "integrity_signature",
)


def _token_regex(token: str) -> str:
    escaped = re.escape(token)
    if "." in token:
        # DEX descriptors use slash-separated class names while JADX and
        # manifests normally use dots. One signature must cover both forms.
        escaped = escaped.replace(r"\.", r"[./]")
        return escaped
    if token.lower().startswith("lib"):
        return rf"(?<![A-Za-z0-9_]){escaped}"
    return rf"(?<![A-Za-z0-9_]){escaped}(?![A-Za-z0-9_])"


def solution_pattern() -> re.Pattern[str]:
    tokens = sorted(
        {indicator.value for item in SIGNATURES for indicator in item.indicators},
        key=len,
        reverse=True,
    )
    return re.compile("|".join(_token_regex(token) for token in tokens), re.I)


def _path_contains(path: str, token: str) -> bool:
    lowered = path.lower()
    target = token.lower()
    return target in lowered or target.replace(".", "/") in lowered


def identify_security_solutions(
    *,
    platform: str,
    matches: Iterable[dict[str, str]],
    native_libraries: Iterable[str],
    archive_entries: Iterable[str] = (),
    control_signals: dict[str, list[dict[str, str]]] | None = None,
) -> list[dict[str, Any]]:
    """Group static evidence by product and calculate an explainable score."""
    hits: dict[str, dict[str, Any]] = {}
    normalized_platform = "ios" if "ios" in platform else "android"

    def record(
        signature: SolutionSignature,
        indicator: SolutionIndicator,
        location: str,
        source: str,
    ) -> None:
        entry = hits.setdefault(
            signature.signature_id,
            {
                "signature_id": signature.signature_id,
                "vendor": signature.vendor,
                "product": signature.product,
                "category": signature.category,
                "category_label": _CATEGORY_LABELS.get(signature.category, signature.category),
                "catalog_version": CATALOG_VERSION,
                "indicators": [],
                "locations": [],
                "evidence": [],
            },
        )
        if indicator.value not in entry["indicators"]:
            entry["indicators"].append(indicator.value)
        if location and location not in entry["locations"] and len(entry["locations"]) < 16:
            entry["locations"].append(location)
        evidence_key = (indicator.value.lower(), indicator.kind, location)
        existing = {
            (item["indicator"].lower(), item["kind"], item["location"])
            for item in entry["evidence"]
        }
        if evidence_key not in existing and len(entry["evidence"]) < 32:
            entry["evidence"].append(
                {
                    "indicator": indicator.value,
                    "kind": indicator.kind,
                    "kind_label": _KIND_LABELS[indicator.kind],
                    "strength": "strong" if indicator.weight >= 0.4 else "supporting",
                    "weight": indicator.weight,
                    "source": source,
                    "location": location,
                }
            )

    eligible = [item for item in SIGNATURES if normalized_platform in item.platforms]
    for item in matches:
        token = str(item.get("match") or "")
        normalized_token = token.replace("/", ".").casefold()
        location = str(item.get("location") or "")
        for signature in eligible:
            for indicator in signature.indicators:
                if normalized_token == indicator.value.casefold():
                    record(signature, indicator, location, "archive_content")

    for path in native_libraries:
        path = str(path)
        for signature in eligible:
            for indicator in signature.indicators:
                if indicator.kind in {"native_library", "framework"} and _path_contains(path, indicator.value):
                    record(signature, indicator, path, "native_inventory")

    for path in archive_entries:
        path = str(path)
        for signature in eligible:
            for indicator in signature.indicators:
                if indicator.kind in {"package", "framework", "native_library"} and _path_contains(path, indicator.value):
                    record(signature, indicator, path, "archive_path")

    # Commercial protectors frequently remove vendor names or integrate the
    # checks directly into the app binary. When at least two independent
    # defensive-control groups remain visible, retain that evidence as an
    # unattributed in-app protection profile instead of reporting that no
    # solution signal exists. A known app-shield fingerprint takes precedence
    # to avoid presenting the same protection twice.
    signals = control_signals or {}
    observed_groups = [key for key in _CUSTOM_CONTROL_GROUPS if signals.get(key)]
    known_app_shield = any(
        entry.get("category") == "app_shield" for entry in hits.values()
    )
    if len(observed_groups) >= 2 and not known_app_shield:
        for group in observed_groups:
            for item in signals[group][:5]:
                token = str(item.get("match") or group)
                record(
                    _CUSTOM_PROTECTION_SIGNATURE,
                    SolutionIndicator(f"{group}:{token}", "control_signal", 0.28),
                    str(item.get("location") or ""),
                    "static_control_signal",
                )

    results: list[dict[str, Any]] = []
    for entry in hits.values():
        strongest_by_indicator: dict[str, float] = {}
        for evidence in entry["evidence"]:
            key = str(evidence["indicator"]).casefold()
            strongest_by_indicator[key] = max(
                strongest_by_indicator.get(key, 0.0), float(evidence["weight"])
            )
        kinds = {str(item["kind"]) for item in entry["evidence"]}
        strong_count = sum(1 for weight in strongest_by_indicator.values() if weight >= 0.4)
        score = 0.18 + min(0.62, sum(strongest_by_indicator.values()))
        score += min(0.12, max(0, len(kinds) - 1) * 0.06)
        if strong_count and len(strongest_by_indicator) > 1:
            score += 0.05
        confidence = round(min(0.97, score), 2)
        entry.update(
            {
                "confidence": confidence,
                "confidence_label": (
                    "high" if confidence >= 0.8 else "medium" if confidence >= 0.6 else "low"
                ),
                "match_count": len(entry["evidence"]),
                "strong_indicator_count": strong_count,
                "evidence_types": sorted(kinds),
                "static_assessment": (
                    "likely_integrated"
                    if strong_count and (len(kinds) >= 2 or len(strongest_by_indicator) >= 2)
                    else "integration_candidate"
                ),
                "expected_control_areas": _EXPECTED_CONTROLS.get(entry["category"], []),
                "verification_status": "dynamic_verification_required",
                "analysis_scope": "static_identification_only",
                "recommended_checks": [
                    "앱 정상 실행 기준 화면·프로세스·로그를 먼저 수집합니다.",
                    "승인된 조건에서 탐지·경고·종료·기능 제한 반응을 관찰합니다.",
                    "제품 버전과 적용 정책은 고객 자료 또는 런타임 증적으로 별도 확인합니다.",
                ],
            }
        )
        if entry["signature_id"] == _CUSTOM_PROTECTION_SIGNATURE.signature_id:
            entry.update(
                {
                    "confidence": min(confidence, 0.79),
                    "confidence_label": "medium",
                    "static_assessment": "unattributed_defensive_controls_observed",
                    "recommended_checks": [
                        "고객 또는 개발팀에 적용 제품·버전·정책을 확인합니다.",
                        "정상 단말과 승인된 탈옥·후킹 조건의 실행 반응을 비교합니다.",
                        "벤더가 확인되기 전에는 특정 상용 제품으로 귀속하지 않습니다.",
                    ],
                }
            )
        results.append(entry)
    results.sort(key=lambda item: (-item["confidence"], item["vendor"], item["product"]))
    return results


def security_solution_summary(solutions: Iterable[dict[str, Any]]) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for raw in solutions:
        item = dict(raw)
        confidence = float(item.get("confidence") or 0.0)
        indicators = [str(value) for value in item.get("indicators") or []]
        locations = [str(value) for value in item.get("locations") or []]
        evidence = item.get("evidence")
        if not isinstance(evidence, list) or any(
            not isinstance(value, dict) for value in evidence
        ):
            evidence = [
                {
                    "indicator": indicator,
                    "kind": "product_marker",
                    "kind_label": _KIND_LABELS["product_marker"],
                    "strength": "supporting",
                    "weight": 0.18,
                    "source": "legacy_static_result",
                    "location": locations[index] if index < len(locations) else (locations[0] if locations else "unknown"),
                }
                for index, indicator in enumerate(indicators)
            ]
        item.setdefault(
            "signature_id",
            re.sub(
                r"[^a-z0-9]+",
                "-",
                f"{item.get('vendor', 'unknown')}-{item.get('product', 'unknown')}".lower(),
            ).strip("-"),
        )
        item.setdefault("catalog_version", CATALOG_VERSION)
        item.setdefault(
            "confidence_label",
            "high" if confidence >= 0.8 else "medium" if confidence >= 0.6 else "low",
        )
        item.setdefault("match_count", len(evidence))
        item.setdefault(
            "strong_indicator_count",
            sum(1 for value in evidence if value.get("strength") == "strong"),
        )
        item.setdefault(
            "evidence_types",
            sorted({str(value.get("kind") or "product_marker") for value in evidence}),
        )
        item.setdefault("static_assessment", "integration_candidate")
        item.setdefault(
            "expected_control_areas",
            _EXPECTED_CONTROLS.get(str(item.get("category") or ""), []),
        )
        item.setdefault("verification_status", "dynamic_verification_required")
        item.setdefault("analysis_scope", "static_identification_only")
        item.setdefault("recommended_checks", [])
        item["evidence"] = evidence
        items.append(item)
    category_counts: dict[str, int] = {}
    for item in items:
        category = str(item.get("category") or "unknown")
        category_counts[category] = category_counts.get(category, 0) + 1
    return {
        "status": "detected" if items else "no_known_signature",
        "catalog_version": CATALOG_VERSION,
        "catalog_signature_count": len(SIGNATURES),
        "detected_count": len(items),
        "high_confidence_count": sum(
            1 for item in items if item.get("confidence_label") == "high"
        ),
        "category_counts": category_counts,
        "solutions": items,
        "limitations": [
            "알려진 정적 지표가 없다는 사실은 보안솔루션 미적용을 의미하지 않습니다.",
            "정적 식별만으로 보호 기능 활성화·정책·우회 가능성을 판정하지 않습니다.",
        ],
    }
