from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


CATALOG_SOURCE = {
    "name": "OWASP Mobile Application Security Testing Guide",
    "repository": "https://github.com/OWASP/owasp-mastg",
    "license": "CC-BY-SA-4.0",
    "metadata_reviewed_at": "2026-07-30",
    "note": "제목과 식별자를 참조하며 진단 절차·판정문은 Workbench에서 자체 작성합니다.",
}


@dataclass(frozen=True, slots=True)
class ControlDefinition:
    mastg_id: str
    platform: str
    masvs_id: str
    title: str
    automation: str
    evaluator: str
    replacement_ids: tuple[str, ...] = field(default_factory=tuple)

    @property
    def source_url(self) -> str:
        group = self.masvs_id.split("-")[1]
        return (
            "https://github.com/OWASP/owasp-mastg/blob/master/tests/"
            f"{self.platform}/MASVS-{group}/{self.mastg_id}.md"
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["replacement_ids"] = list(self.replacement_ids)
        data["source_url"] = self.source_url
        return data


def _c(
    mastg_id: str,
    platform: str,
    masvs_id: str,
    title: str,
    automation: str,
    evaluator: str,
    *replacement_ids: str,
) -> ControlDefinition:
    return ControlDefinition(
        mastg_id,
        platform,
        masvs_id,
        title,
        automation,
        evaluator,
        replacement_ids,
    )


MASTG_CONTROLS: tuple[ControlDefinition, ...] = (
    _c("MASTG-TEST-0001", "android", "MASVS-STORAGE-1", "로컬 저장소의 민감정보 점검", "hybrid", "local_storage"),
    _c("MASTG-TEST-0003", "android", "MASVS-STORAGE-2", "로그의 민감정보 점검", "dynamic", "logs"),
    _c("MASTG-TEST-0009", "android", "MASVS-STORAGE-2", "민감정보 백업 설정 점검", "static", "android_backup", "MASTG-TEST-0216"),
    _c("MASTG-TEST-0010", "android", "MASVS-PLATFORM-3", "자동 화면 캡처 민감정보 점검", "dynamic", "background_screen"),
    _c("MASTG-TEST-0013", "android", "MASVS-CRYPTO-1", "대칭키 암호화 구현 점검", "hybrid", "crypto"),
    _c("MASTG-TEST-0020", "android", "MASVS-NETWORK-1", "TLS 설정 점검", "hybrid", "tls"),
    _c("MASTG-TEST-0022", "android", "MASVS-NETWORK-2", "인증서 저장소·고정 점검", "hybrid", "certificate_pinning", "MASTG-TEST-0242", "MASTG-TEST-0243", "MASTG-TEST-0244"),
    _c("MASTG-TEST-0024", "android", "MASVS-PLATFORM-1", "앱 권한 점검", "static", "permissions"),
    _c("MASTG-TEST-0028", "android", "MASVS-PLATFORM-1", "딥링크 점검", "hybrid", "deep_links"),
    _c("MASTG-TEST-0029", "android", "MASVS-PLATFORM-1", "IPC 노출 기능 점검", "hybrid", "exported_components", "MASTG-TEST-0364", "MASTG-TEST-0365", "MASTG-TEST-0366"),
    _c("MASTG-TEST-0031", "android", "MASVS-PLATFORM-2", "WebView JavaScript 실행 점검", "static", "webview"),
    _c("MASTG-TEST-0033", "android", "MASVS-PLATFORM-2", "WebView Java 객체 노출 점검", "hybrid", "javascript_interface"),
    _c("MASTG-TEST-0038", "android", "MASVS-RESILIENCE-3", "앱 서명 점검", "static", "signature"),
    _c("MASTG-TEST-0039", "android", "MASVS-RESILIENCE-4", "디버그 가능 앱 점검", "static", "debuggable", "MASTG-TEST-0226", "MASTG-TEST-0227"),
    _c("MASTG-TEST-0045", "android", "MASVS-RESILIENCE-1", "루팅 탐지 내성 점검", "dynamic", "root_detection", "MASTG-TEST-0324", "MASTG-TEST-0325"),
    _c("MASTG-TEST-0046", "android", "MASVS-RESILIENCE-2", "안티 디버깅 내성 점검", "dynamic", "debugger_detection"),
    _c("MASTG-TEST-0047", "android", "MASVS-RESILIENCE-3", "파일 무결성 점검", "hybrid", "integrity"),
    _c("MASTG-TEST-0048", "android", "MASVS-RESILIENCE-2", "Frida·후킹 도구 탐지 점검", "dynamic", "frida_detection"),
    _c("MASTG-TEST-0049", "android", "MASVS-RESILIENCE-1", "에뮬레이터 탐지 점검", "dynamic", "emulator_detection"),
    _c("MASTG-TEST-0051", "android", "MASVS-RESILIENCE-3", "난독화 점검", "static", "obfuscation"),
    _c("MASTG-TEST-0052", "ios", "MASVS-STORAGE-1", "iOS 로컬 저장소 점검", "hybrid", "local_storage", "MASTG-TEST-0299", "MASTG-TEST-0300", "MASTG-TEST-0301", "MASTG-TEST-0302", "MASTG-TEST-0303"),
    _c("MASTG-TEST-0053", "ios", "MASVS-STORAGE-2", "iOS 로그의 민감정보 점검", "dynamic", "logs"),
    _c("MASTG-TEST-0059", "ios", "MASVS-PLATFORM-3", "백그라운드 화면 노출 점검", "dynamic", "background_screen"),
    _c("MASTG-TEST-0061", "ios", "MASVS-CRYPTO-1", "iOS 암호화 알고리즘 점검", "hybrid", "crypto"),
    _c("MASTG-TEST-0066", "ios", "MASVS-NETWORK-1", "iOS TLS 설정 점검", "hybrid", "tls"),
    _c("MASTG-TEST-0068", "ios", "MASVS-NETWORK-2", "iOS 인증서 저장소·고정 점검", "hybrid", "certificate_pinning"),
    _c("MASTG-TEST-0069", "ios", "MASVS-PLATFORM-1", "iOS 앱 권한 점검", "static", "permissions"),
    _c("MASTG-TEST-0070", "ios", "MASVS-PLATFORM-1", "Universal Link 점검", "hybrid", "deep_links"),
    _c("MASTG-TEST-0073", "ios", "MASVS-PLATFORM-3", "클립보드 점검", "dynamic", "clipboard"),
    _c("MASTG-TEST-0075", "ios", "MASVS-PLATFORM-1", "사용자 정의 URL Scheme 점검", "hybrid", "deep_links"),
    _c("MASTG-TEST-0076", "ios", "MASVS-PLATFORM-2", "WKWebView 점검", "hybrid", "webview"),
    _c("MASTG-TEST-0078", "ios", "MASVS-PLATFORM-2", "WebView 네이티브 메서드 노출 점검", "hybrid", "javascript_interface"),
    _c("MASTG-TEST-0081", "ios", "MASVS-RESILIENCE-3", "iOS 앱 서명 점검", "static", "signature"),
    _c("MASTG-TEST-0088", "ios", "MASVS-RESILIENCE-1", "탈옥 탐지 내성 점검", "dynamic", "root_detection", "MASTG-TEST-0240", "MASTG-TEST-0241"),
    _c("MASTG-TEST-0089", "ios", "MASVS-RESILIENCE-2", "iOS 안티 디버깅 내성 점검", "dynamic", "debugger_detection"),
    _c("MASTG-TEST-0090", "ios", "MASVS-RESILIENCE-3", "iOS 파일 무결성 점검", "hybrid", "integrity"),
    _c("MASTG-TEST-0091", "ios", "MASVS-RESILIENCE-2", "iOS Frida·후킹 탐지 점검", "dynamic", "frida_detection"),
    _c("MASTG-TEST-0092", "ios", "MASVS-RESILIENCE-1", "시뮬레이터 탐지 점검", "dynamic", "emulator_detection"),
    _c("MASTG-TEST-0093", "ios", "MASVS-RESILIENCE-3", "iOS 난독화 점검", "static", "obfuscation"),
)


def evaluate_controls(
    platform: str,
    analysis: dict[str, Any],
) -> list[dict[str, Any]]:
    signals = analysis.get("signals") or {}
    manifest = analysis.get("manifest") or {}
    permissions = analysis.get("permissions") or []
    components = analysis.get("components") or []
    deep_links = analysis.get("deep_links") or []
    native_libraries = analysis.get("native_libraries") or []

    evaluated: list[dict[str, Any]] = []
    for definition in MASTG_CONTROLS:
        if definition.platform != platform:
            continue
        status = "manual_required"
        result = "not_tested"
        summary = "단말에서 수동 또는 승인 기반 동적 검증이 필요합니다."
        evaluator = definition.evaluator

        if evaluator == "debuggable":
            if manifest.get("debuggable") is None:
                status, result = "not_configured", "unknown"
                summary = "Manifest의 debuggable 값을 해석하지 못했습니다."
            else:
                status = "completed"
                result = "fail" if manifest.get("debuggable") else "pass"
                summary = f"android:debuggable={str(manifest.get('debuggable')).lower()}"
        elif evaluator == "android_backup":
            if manifest.get("allow_backup") is None:
                status, result = "not_configured", "unknown"
                summary = "Manifest의 allowBackup 값을 해석하지 못했습니다."
            else:
                status = "completed"
                result = "needs_review" if manifest.get("allow_backup") else "pass"
                summary = f"android:allowBackup={str(manifest.get('allow_backup')).lower()}"
        elif evaluator == "permissions":
            status, result = "completed", "needs_review" if permissions else "pass"
            summary = f"선언 권한 {len(permissions)}개를 식별했습니다."
        elif evaluator == "exported_components":
            exposed = [
                item
                for item in components
                if item.get("exported") and not item.get("permission")
            ]
            status, result = "completed", "needs_review" if exposed else "pass"
            summary = f"권한 보호 없는 외부 노출 컴포넌트 {len(exposed)}개"
        elif evaluator == "deep_links":
            status, result = "completed", "needs_review" if deep_links else "pass"
            summary = f"딥링크·URL Scheme {len(deep_links)}개"
        elif evaluator == "signature":
            status, result = "completed", "needs_review"
            summary = (
                f"네이티브 라이브러리 {len(native_libraries)}개와 서명·무결성 신호를 "
                "정적 수집했으며 서명 체인은 별도 확인이 필요합니다."
            )
        elif evaluator in {
            "local_storage",
            "crypto",
            "certificate_pinning",
            "webview",
            "javascript_interface",
            "debugger_detection",
            "integrity",
            "obfuscation",
        }:
            signal_key = {
                "debugger_detection": "debugger_detection",
                "integrity": "integrity_signature",
            }.get(evaluator, evaluator)
            count = len(signals.get(signal_key, []))
            status = "completed" if definition.automation == "static" else "manual_required"
            result = "needs_review" if count else ("pass" if status == "completed" else "not_tested")
            summary = f"관련 정적 신호 {count}개를 식별했습니다."

        item = definition.to_dict()
        item.update({"status": status, "result": result, "summary": summary})
        evaluated.append(item)
    return evaluated
