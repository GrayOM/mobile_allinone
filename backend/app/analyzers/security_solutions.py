"""Identify commercial mobile security solutions bundled in an APK/IPA.

Detection only: the result names the vendor product and the indicators that
matched (package/class prefixes, native library names, marker strings) so
the analyst knows which protection family is present. It never decides
whether the protection works and never changes how a Run behaves.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass(frozen=True, slots=True)
class SolutionSignature:
    vendor: str
    product: str
    category: str
    platforms: tuple[str, ...]
    indicators: tuple[str, ...]


# Categories: app_shield (RASP/anti-tamper bundle), obfuscator, secure_keypad,
# anti_malware, mobile_threat_defense.
SIGNATURES: tuple[SolutionSignature, ...] = (
    SolutionSignature("INKA Entworks", "AppSealing", "app_shield", ("android", "ios"), ("com.inka.appsealing", "libcovault", "appsealing", "AppSealing")),
    SolutionSignature("Lockin Company", "LIAPP", "app_shield", ("android", "ios"), ("com.lockincomp", "libliapp", "LIAPP", "liapp")),
    SolutionSignature("Licel", "DexProtector", "obfuscator", ("android", "ios"), ("com.licel", "dexprotector", "DexProtector")),
    SolutionSignature("Guardsquare", "DexGuard", "obfuscator", ("android",), ("dexguard", "DexGuard")),
    SolutionSignature("Guardsquare", "iXGuard", "obfuscator", ("ios",), ("ixguard", "iXGuard")),
    SolutionSignature("Promon", "SHIELD", "app_shield", ("android", "ios"), ("no.promon.shield", "libshield", "promon", "Promon")),
    SolutionSignature("Digital.ai (Arxan)", "App Protection", "app_shield", ("android", "ios"), ("com.arxan", "libarxan", "arxan", "digital.ai")),
    SolutionSignature("Appdome", "Appdome", "app_shield", ("android", "ios"), ("appdome", "Appdome")),
    SolutionSignature("Zimperium", "zIAP / zDefend", "mobile_threat_defense", ("android", "ios"), ("com.zimperium", "zimperium", "zDefend", "zIAP")),
    SolutionSignature("Verimatrix", "XTD / App Shield", "app_shield", ("android", "ios"), ("com.insidesecure", "verimatrix", "Verimatrix")),
    SolutionSignature("AhnLab", "V3 Mobile Plus", "anti_malware", ("android",), ("com.ahnlab.v3mobileplus", "V3MobilePlus", "v3mobileplus")),
    SolutionSignature("Inca Internet", "nProtect AppGuard", "app_shield", ("android", "ios"), ("com.nprotect", "nprotect", "nProtect", "AppGuard")),
    SolutionSignature("RaonSecure", "TouchEn mTransKey", "secure_keypad", ("android", "ios"), ("com.raon", "mtranskey", "mTransKey", "TouchEn")),
    SolutionSignature("Softcamp / Secuve", "Secure keypad (ETC)", "secure_keypad", ("android", "ios"), ("securekeypad", "SecureKeypad", "com.softforum", "com.secuve")),
    SolutionSignature("STEALIEN", "AppSuit", "app_shield", ("android", "ios"), ("com.stealien", "stealien", "AppSuit", "libappsuit")),
    SolutionSignature("Everspin", "EverSafe", "anti_malware", ("android", "ios"), ("com.everspin", "everspin", "EverSafe")),
    SolutionSignature("SK Infosec / Unify", "DroidX", "app_shield", ("android",), ("droidx", "DroidX", "libdroidx")),
    SolutionSignature("Bangcle / SecNeo", "Bangcle", "app_shield", ("android",), ("com.secneo", "libsecexe", "libsecmain", "bangcle")),
    SolutionSignature("Tencent", "Legu", "app_shield", ("android",), ("com.tencent.legu", "libshella", "libshellx")),
    SolutionSignature("Qihoo 360", "Jiagu", "app_shield", ("android",), ("com.qihoo.util", "libjiagu", "jiagu")),
    SolutionSignature("NHN Cloud / NSHC", "AppGuard (NSHC)", "app_shield", ("android", "ios"), ("com.nshc", "nshc", "droidx", )),
)

_CATEGORY_LABELS = {
    "app_shield": "앱 무결성·안티탬퍼(RASP)",
    "obfuscator": "난독화·코드 보호",
    "secure_keypad": "보안 키패드",
    "anti_malware": "안티바이러스·악성앱 탐지",
    "mobile_threat_defense": "모바일 위협 탐지",
}


def _token_regex(token: str) -> str:
    # Package prefixes and library names may continue (com.inka.appsealing.Foo,
    # libliapp-arm64.so); bare product words must stand alone so that
    # "nProtect" never matches inside "ApplicationProtection".
    escaped = re.escape(token)
    if "." in token or token.lower().startswith("lib"):
        return rf"(?<![A-Za-z0-9_]){escaped}"
    return rf"(?<![A-Za-z0-9_]){escaped}(?![A-Za-z0-9_])"


def solution_pattern() -> re.Pattern[str]:
    tokens = sorted({token for item in SIGNATURES for token in item.indicators}, key=len, reverse=True)
    return re.compile("|".join(_token_regex(token) for token in tokens))


def identify_security_solutions(
    *,
    platform: str,
    matches: Iterable[dict[str, str]],
    native_libraries: Iterable[str],
) -> list[dict[str, Any]]:
    """Group indicator hits by vendor product for the app's platform."""
    hits: dict[str, dict[str, Any]] = {}
    normalized_platform = "ios" if "ios" in platform else "android"
    libraries = [str(item) for item in native_libraries]

    def record(signature: SolutionSignature, token: str, location: str) -> None:
        key = f"{signature.vendor}:{signature.product}"
        entry = hits.setdefault(
            key,
            {
                "vendor": signature.vendor,
                "product": signature.product,
                "category": signature.category,
                "category_label": _CATEGORY_LABELS.get(signature.category, signature.category),
                "indicators": [],
                "locations": [],
            },
        )
        if token not in entry["indicators"]:
            entry["indicators"].append(token)
        if location and location not in entry["locations"] and len(entry["locations"]) < 12:
            entry["locations"].append(location)

    for item in matches:
        token = str(item.get("match") or "")
        location = str(item.get("location") or "")
        for signature in SIGNATURES:
            if normalized_platform not in signature.platforms:
                continue
            if any(token == indicator or token.lower() == indicator.lower() for indicator in signature.indicators):
                record(signature, token, location)
    for library in libraries:
        lowered = library.lower()
        for signature in SIGNATURES:
            if normalized_platform not in signature.platforms:
                continue
            for indicator in signature.indicators:
                if indicator.lower().startswith("lib") and indicator.lower() in lowered:
                    record(signature, indicator, library)
    results = []
    for entry in hits.values():
        distinct = len(entry["indicators"])
        entry["confidence"] = round(min(0.95, 0.45 + 0.15 * distinct), 2)
        entry["verification_status"] = "dynamic_verification_required"
        results.append(entry)
    results.sort(key=lambda item: (-item["confidence"], item["vendor"]))
    return results
