from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable


CRITICAL_INFRASTRUCTURE = "critical_infrastructure"
ELECTRONIC_FINANCIAL = "electronic_financial"
DEFAULT_ASSESSMENT_PROFILE = CRITICAL_INFRASTRUCTURE


PROFILE_SOURCES: dict[str, dict[str, Any]] = {
    CRITICAL_INFRASTRUCTURE: {
        "id": CRITICAL_INFRASTRUCTURE,
        "name": "주요정보통신기반시설",
        "document": "[주요정보통신기반시설] 모바일 앱 취약점 보안 권고안.docx",
        "reviewed_at": "2026-08-20",
        "item_count": 27,
        "note": "제공된 보고서 템플릿의 항목명과 진단 기준을 로컬 실행·증적 정책으로 요약했습니다.",
    },
    ELECTRONIC_FINANCIAL: {
        "id": ELECTRONIC_FINANCIAL,
        "name": "전자금융기반시설",
        "document": "[전자금융기반시설] 모바일 앱 취약점 보안 권고안_2026_v0.9.docx",
        "version": "2026 v0.9",
        "reviewed_at": "2026-08-20",
        "item_count": 56,
        "note": "제공된 보고서 템플릿의 항목명과 진단 기준을 로컬 실행·증적 정책으로 요약했습니다.",
    },
}


@dataclass(frozen=True, slots=True)
class StandardControlDefinition:
    profile: str
    control_id: str
    group: str
    title: str
    criteria: tuple[str, ...]
    automation: str
    evaluator: str
    risk: str
    evidence_requirements: tuple[tuple[str, ...], ...]
    finding_categories: tuple[str, ...]
    severity: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["criteria"] = list(self.criteria)
        value["evidence_requirements"] = [
            list(group) for group in self.evidence_requirements
        ]
        value["finding_categories"] = list(self.finding_categories)
        return value


def _requirements(evaluator: str) -> tuple[tuple[str, ...], ...]:
    mapping = {
        "static_review": (("static_analysis",),),
        "root_execution": (
            ("device_state",),
            ("screenshot",),
            ("device_log", "command_log"),
        ),
        "local_storage": (("storage_snapshot", "storage_diff"),),
        "memory_exposure": (
            ("frida_session", "runtime_tool", "manual_assessment_attachment"),
        ),
        "runtime_logs": (("device_log", "frida_session"),),
        "forced_screen": (
            ("component_validation_result", "manual_assessment_attachment"),
            ("component_validation_before", "screenshot"),
            ("component_validation_after", "screenshot"),
        ),
        "deep_link": (
            ("component_validation_result", "manual_assessment_attachment"),
            ("component_validation_before", "screenshot"),
            ("component_validation_after", "screenshot"),
        ),
        "network_plaintext": (("network_capture", "manual_proxy_import"),),
        "network_review": (("network_capture", "network_test", "manual_proxy_import"),),
        "ui_review": (("screenshot", "ui_tree", "manual_assessment_attachment"),),
        "dynamic_review": (
            ("screenshot", "runtime_tool", "manual_assessment_attachment"),
        ),
        "manual": (("manual_assessment_attachment",),),
    }
    return mapping.get(evaluator, (("manual_assessment_attachment",),))


def _d(
    profile: str,
    number: int,
    group: str,
    title: str,
    criteria: str | Iterable[str],
    automation: str,
    evaluator: str,
    risk: str,
    categories: str | Iterable[str],
    severity: str = "medium",
) -> StandardControlDefinition:
    prefix = "CII-MA" if profile == CRITICAL_INFRASTRUCTURE else "EFI-MA"
    criteria_values = (criteria,) if isinstance(criteria, str) else tuple(criteria)
    category_values = (categories,) if isinstance(categories, str) else tuple(categories)
    return StandardControlDefinition(
        profile=profile,
        control_id=f"{prefix}-{number:02d}",
        group=group,
        title=title,
        criteria=criteria_values,
        automation=automation,
        evaluator=evaluator,
        risk=risk,
        evidence_requirements=_requirements(evaluator),
        finding_categories=category_values,
        severity=severity,
    )


_CII = CRITICAL_INFRASTRUCTURE
_EFI = ELECTRONIC_FINANCIAL


CRITICAL_INFRASTRUCTURE_CONTROLS: tuple[StandardControlDefinition, ...] = (
    _d(_CII, 1, "입력값·서버 실행", "코드 인젝션 (Code Injection)", "LDAP·OS 명령·SSI·XPath·XXE·SSTI 입력이 서버에서 실행되거나 비인가 정보가 반환되는지 확인한다.", "manual", "manual", "high", ("code_injection", "command_injection", "xxe", "ssti"), "high"),
    _d(_CII, 2, "입력값·서버 실행", "SQL 인젝션 (SQL Injection)", "URL·XML 등 입력값이 SQL로 해석되어 데이터 조회·인증 우회·명령 실행이 가능한지 확인한다.", "manual", "manual", "high", "sql_injection", "high"),
    _d(_CII, 3, "정보 노출", "디렉터리 인덱싱", "디렉터리 URL 요청 시 하위 파일과 디렉터리 목록이 노출되는지 확인한다.", "manual", "network_review", "medium", "directory_listing"),
    _d(_CII, 4, "정보 노출", "에러 페이지 적용 미흡", "오류 응답에 서버 버전·절대경로·스택 트레이스 등 운영정보가 노출되는지 확인한다.", "hybrid", "network_review", "low", "system_information_exposure", "low"),
    _d(_CII, 5, "정보 노출", "정보 누출", "화면·응답·소스·샘플·백업 파일에서 개인정보 또는 운영정보가 노출되는지 확인한다.", "hybrid", "static_review", "medium", "sensitive_data_exposure"),
    _d(_CII, 6, "입력값·서버 실행", "크로스사이트 스크립트", "저장되거나 반사된 입력 스크립트가 다른 이용자의 브라우저·WebView에서 실행되는지 확인한다.", "manual", "manual", "high", "xss"),
    _d(_CII, 7, "거래·권한", "크로스사이트 요청 변조(CSRF)", "공격자가 만든 요청으로 로그인 이용자의 권한을 도용해 수정·삭제·등록·송금이 가능한지 확인한다.", "manual", "manual", "high", "csrf", "high"),
    _d(_CII, 8, "입력값·서버 실행", "서버사이드 요청 변조(SSRF)", "URL·IP 입력값 변조로 서버가 내부망이나 로컬 자원에 요청하고 응답을 반환하는지 확인한다.", "manual", "manual", "high", "ssrf", "high"),
    _d(_CII, 9, "인증·인가", "약한 비밀번호 정책", "단순·유추 가능한 계정과 비밀번호 조합으로 등록 또는 인증이 가능한지 확인한다.", "manual", "manual", "medium", "weak_password"),
    _d(_CII, 10, "인증·인가", "불충분한 인증 절차", "민감 기능과 중요정보 접근 시 재인증·이중인증이 없거나 우회되는지 확인한다.", "manual", "manual", "high", "authentication", "high"),
    _d(_CII, 11, "인증·인가", "불충분한 권한 검증", "이용자·객체 파라미터 변조로 타인의 정보를 조회·수정하거나 권한이 상승하는지 확인한다.", "manual", "manual", "high", "authorization", "high"),
    _d(_CII, 12, "인증·인가", "취약한 비밀번호 복구 절차", "비밀번호 초기화 규칙이 예측 가능하거나 타 계정 초기화 및 본인확인 우회가 가능한지 확인한다.", "manual", "manual", "high", "password_recovery", "high"),
    _d(_CII, 13, "인증·인가", "프로세스 검증 누락", "중간 인증 단계를 생략하거나 URL·클라이언트 로직·파라미터를 변조해 중요 기능에 접근 가능한지 확인한다.", "manual", "manual", "high", "authentication_flow", "high"),
    _d(_CII, 14, "파일 처리", "악성 파일 업로드", "허용되지 않은 실행 파일을 업로드하고 서버에서 실행하거나 접근할 수 있는지 승인된 환경에서 확인한다.", "manual", "manual", "blocked", "malicious_file_upload", "critical"),
    _d(_CII, 15, "파일 처리", "파일 다운로드", "다운로드 경로 변조로 허용 디렉터리 밖의 소스·설정·중요 파일을 내려받을 수 있는지 확인한다.", "manual", "manual", "high", "arbitrary_file_download", "high"),
    _d(_CII, 16, "세션·전송", "불충분한 세션 관리", "세션·JWT의 예측 가능성, 만료, 로그아웃 파기, 서명·알고리즘 변조 가능성을 확인한다.", "manual", "network_review", "high", "session_management", "high"),
    _d(_CII, 17, "세션·전송", "데이터 평문 전송", "프록시 캡처에서 개인정보·인증정보·금융정보가 암호화되지 않은 채 전송되는지 확인한다.", "dynamic", "network_plaintext", "medium", "network_sensitive_exposure", "high"),
    _d(_CII, 18, "세션·전송", "쿠키 변조", "쿠키의 계정·권한 정보를 변조해 타 이용자 권한 또는 데이터 조작이 가능한지 확인한다.", "manual", "manual", "high", "cookie_tampering", "high"),
    _d(_CII, 19, "노출 서비스", "관리자 페이지 노출", "유추 가능한 경로·관리 포트에서 관리자 화면이 노출되고 접근통제가 우회되는지 확인한다.", "manual", "network_review", "medium", "admin_page_exposure"),
    _d(_CII, 20, "서비스 남용", "자동화 공격", "데이터 등록·메시지 발송 등 반복 기능이 제한 없이 자동화되는지 승인 후 확인한다.", "manual", "manual", "blocked", "unlimited_requests", "high"),
    _d(_CII, 21, "노출 서비스", "불필요한 Method 악용", "PUT·DELETE·TRACE·CONNECT 등 불필요한 메서드로 파일 생성·삭제·정보 노출이 가능한지 확인한다.", "manual", "manual", "blocked", "unsafe_http_method", "high"),
    _d(_CII, 22, "모바일 보안통제", "OS 변조 탐지 기능 적용 여부", "루팅 Android 또는 탈옥 iOS 단말에서 앱이 차단되지 않고 정상 실행되는지 확인한다.", "dynamic", "root_execution", "medium", ("root_detection", "jailbreak_detection"), "high"),
    _d(_CII, 23, "모바일 보안통제", "소스코드 난독화 적용 여부", "대상 앱 디컴파일 결과의 클래스·함수·문자열과 코드 흐름을 쉽게 파악할 수 있는지 확인한다.", "static", "static_review", "low", "obfuscation", "medium"),
    _d(_CII, 24, "단말 중요정보", "단말기 내 중요정보 저장 여부", "앱 전용·외부 저장소의 파일과 DB에 개인정보·금융정보·인증정보가 저장되는지 확인한다.", "hybrid", "local_storage", "medium", "local_storage", "high"),
    _d(_CII, 25, "단말 중요정보", "메모리 내 중요정보 노출 여부", "메모리 덤프에서 입력한 개인정보·금융정보·비밀번호가 평문으로 남는지 확인한다.", "manual", "memory_exposure", "high", "memory_sensitive_exposure", "high"),
    _d(_CII, 26, "모바일 인증경계", "화면 강제실행에 의한 인증단계 우회", "Intent·URL Scheme·Cycript 또는 인증 파일 변조로 인증 화면을 건너뛰고 정상 서비스를 이용할 수 있는지 확인한다.", "hybrid", "forced_screen", "high", ("navigation", "deep_link", "authorization"), "high"),
    _d(_CII, 27, "단말 중요정보", "디버그 로그 내 중요정보 노출 여부", "단말 디버그 로그에 개인정보·고유식별정보·비밀번호·금융정보가 기록되는지 확인한다.", "dynamic", "runtime_logs", "low", "runtime_log_exposure", "high"),
)


ELECTRONIC_FINANCIAL_CONTROLS: tuple[StandardControlDefinition, ...] = (
    _d(_EFI, 1, "전자금융 거래", "[전자금융] 거래 인증수단 검증 오류", "잘못되거나 폐기·만료된 비밀번호·OTP·보안카드·인증서로 거래가 승인되는지 확인한다.", "manual", "manual", "blocked", "transaction_authentication", "critical"),
    _d(_EFI, 2, "전자금융 거래", "[전자금융] 거래정보 무결성 검증", "예비·본·최종 거래정보와 전자서명·계좌·금액을 변조해도 거래가 승인되는지 확인한다.", "manual", "manual", "blocked", "transaction_integrity", "critical"),
    _d(_EFI, 3, "전자금융 거래", "[전자금융] 거래정보 재사용", "과거 이체·결제 전문이나 암호·해시 값을 재전송해 거래가 다시 처리되는지 확인한다.", "manual", "manual", "blocked", "transaction_replay", "critical"),
    _d(_EFI, 4, "전자금융 거래", "[전자금융] 거래시 소유주 확인 여부", "타 이용자의 계좌·카드·계약 번호로 조회 또는 거래가 가능한지 확인한다.", "manual", "manual", "blocked", "authorization", "critical"),
    _d(_EFI, 5, "전자금융 인증", "[전자금융] 비밀번호 변경 시 본인확인 절차 실시 여부", "비밀번호 변경 전 본인확인이 없거나 우회 가능한지 확인한다.", "manual", "manual", "high", "authentication", "high"),
    _d(_EFI, 6, "전자금융 인증", "[전자금융] 비밀번호 변경 시 이전 비밀번호 재사용 여부", "전자금융 비밀번호를 이전 값으로 다시 변경할 수 있는지 확인한다.", "manual", "manual", "medium", "weak_password"),
    _d(_EFI, 7, "모바일 보안통제", "[전자금융] OS 변조 탐지 기능 적용 여부", "루팅 Android 또는 탈옥 iOS 단말에서 전자금융 서비스를 정상 이용할 수 있는지 확인한다.", "dynamic", "root_execution", "medium", ("root_detection", "jailbreak_detection"), "critical"),
    _d(_EFI, 8, "모바일 보안통제", "[전자금융] 악성코드 방지", "악성코드 탐지 프로세스가 동작하고 강제 종료 후에도 재구동·차단되는지 확인한다.", "manual", "dynamic_review", "high", "malware_protection", "high"),
    _d(_EFI, 9, "모바일 보안통제", "[전자금융] 이용자 입력정보 보호", "금융정보 입력 구간에 가상 키패드·키보드 보호 등 정해진 보호수단이 일관되게 적용되는지 확인한다.", "manual", "ui_review", "medium", "input_protection", "high"),
    _d(_EFI, 10, "모바일 보안통제", "[전자금융] 프로그램 무결성 검증", "변조한 APK·IPA·실행 파일·라이브러리를 설치한 뒤 앱이 정상 실행되는지 확인한다.", "manual", "dynamic_review", "high", "integrity", "critical"),
    _d(_EFI, 11, "모바일 보안통제", "[전자금융] 소스코드 난독화 적용 여부", "대상 앱 디컴파일 결과의 클래스·함수·문자열과 코드 흐름을 쉽게 파악할 수 있는지 확인한다.", "static", "static_review", "low", "obfuscation", "medium"),
    _d(_EFI, 12, "모바일 보안통제", "[전자금융] 디버깅 탐지기능 적용 여부", "gdb·lldb 등 디버거를 연결한 상태에서도 앱이 차단되지 않고 정상 실행되는지 확인한다.", "manual", "dynamic_review", "medium", "debugger_detection", "high"),
    _d(_EFI, 13, "전자금융 인증", "[전자금융] 접근매체 발급 시 실명확인 수행 여부", "접근매체 발급 과정이 요구된 복수의 실명확인 수단을 적용하고 비인가 발급을 차단하는지 확인한다.", "manual", "manual", "blocked", "identity_verification", "critical"),
    _d(_EFI, 14, "입력값·서버 실행", "SQL Injection", "URL·XML·XPath 입력값 변조로 DB 조회·인증 우회·명령 실행이 가능한지 확인한다.", "manual", "manual", "high", "sql_injection", "high"),
    _d(_EFI, 15, "파일 처리", "악성파일 업로드", "허용되지 않은 실행 파일을 업로드하고 서버에서 실행하거나 접근할 수 있는지 승인된 환경에서 확인한다.", "manual", "manual", "blocked", "malicious_file_upload", "critical"),
    _d(_EFI, 16, "인증·인가", "부적절한 이용자 인가 여부", "이용자·객체 파라미터를 바꿔 타인의 정보를 조회·수정하거나 권한을 상승시킬 수 있는지 확인한다.", "manual", "manual", "high", "authorization", "critical"),
    _d(_EFI, 17, "인증·인가", "이용자 인증정보 재사용", "전자서명·OTP·SMS·계좌인증·신분증 정보 등 이미 사용한 인증정보를 재사용할 수 있는지 확인한다.", "manual", "manual", "blocked", "authentication_replay", "critical"),
    _d(_EFI, 18, "인증·인가", "고정된 인증정보 이용", "SMS·ARS 등 인증코드가 매번 동일하거나 고정값으로 생성되는지 확인한다.", "manual", "manual", "medium", "fixed_authentication"),
    _d(_EFI, 19, "인증·인가", "유추가능한 인증정보 이용", "개인정보·연속·동일 문자 등 유추 가능한 인증정보와 미흡한 비밀번호 복잡도를 허용하는지 확인한다.", "manual", "manual", "medium", "weak_password", "high"),
    _d(_EFI, 20, "인증·인가", "유추가능한 초기화 비밀번호 이용", "초기화 비밀번호 규칙을 예측하거나 타인의 초기화 기능을 실행해 계정 접근이 가능한지 확인한다.", "manual", "manual", "high", "password_recovery", "high"),
    _d(_EFI, 21, "단말 중요정보", "단말기 내 중요정보 저장 여부", "앱 전용·외부 저장소의 파일과 DB에 개인정보·금융정보·인증정보가 저장되는지 확인한다.", "hybrid", "local_storage", "medium", "local_storage", "high"),
    _d(_EFI, 22, "단말 중요정보", "메모리 내 중요정보 노출 여부", "메모리 덤프에서 화면에 보이지 않는 계좌·비밀번호 등 중요정보가 평문으로 남는지 확인한다.", "manual", "memory_exposure", "high", "memory_sensitive_exposure", "high"),
    _d(_EFI, 23, "파일 처리", "파일 다운로드", "다운로드 경로 변조로 허용 디렉터리 밖의 소스·설정·중요 파일을 내려받을 수 있는지 확인한다.", "manual", "manual", "high", "arbitrary_file_download", "high"),
    _d(_EFI, 24, "정보 노출", "외부사이트에 의한 시스템 운영정보 노출 여부", "검색엔진과 외부 분석 서비스에서 대상 시스템의 운영정보·자산이 노출되는지 확인한다.", "manual", "manual", "low", "external_information_exposure", "medium"),
    _d(_EFI, 25, "세션·전송", "유추 가능한 세션ID", "세션 ID가 짧거나 순차적·규칙적이어서 무차별 대입으로 추측 가능한지 확인한다.", "manual", "network_review", "medium", "session_management", "high"),
    _d(_EFI, 26, "세션·전송", "쿠키 변조", "쿠키의 계정·권한·인증 식별자를 변조해 타 이용자 권한을 얻을 수 있는지 확인한다.", "manual", "manual", "high", "cookie_tampering", "high"),
    _d(_EFI, 27, "입력값·서버 실행", "운영체제 명령 실행", "서버 명령 인터페이스에서 허용된 명령 외의 임의 OS 명령을 실행할 수 있는지 확인한다.", "manual", "manual", "high", "command_injection", "critical"),
    _d(_EFI, 28, "입력값·서버 실행", "XML 외부객체 공격(XXE)", "외부 엔터티가 포함된 XML로 로컬 파일·내부망·외부 자원을 읽거나 요청할 수 있는지 확인한다.", "manual", "manual", "high", "xxe", "high"),
    _d(_EFI, 29, "입력값·서버 실행", "리다이렉트 기능을 이용한 피싱 공격", "리다이렉트 URL 인자를 임의 외부 페이지로 바꿔 이동시킬 수 있는지 확인한다.", "manual", "network_review", "medium", "open_redirect"),
    _d(_EFI, 30, "인증·인가", "불충분한 이용자 인증", "URL·클라이언트 스크립트·단계 순서를 조작해 재인증과 인증 플로우를 우회할 수 있는지 확인한다.", "manual", "manual", "high", "authentication", "critical"),
    _d(_EFI, 31, "단말 중요정보", "화면 내 중요정보 평문노출 여부", "화면에서 계좌·카드·인증정보 등 중요정보가 불필요하게 평문 노출되는지 확인한다.", "dynamic", "ui_review", "low", "screen_sensitive_exposure", "high"),
    _d(_EFI, 32, "서비스 남용", "무제한 요청 허용", "SMS·메일·1원 이체·글쓰기·업로드 등 비용·자원을 쓰는 기능이 제한 없이 반복되는지 승인 후 확인한다.", "manual", "manual", "blocked", "unlimited_requests", "high"),
    _d(_EFI, 33, "정보 노출", "앱 소스코드 내 운영정보 노출 여부", "디컴파일한 앱에서 서버 계정·비밀번호·고정 암호키 등 운영정보가 노출되는지 확인한다.", "static", "static_review", "low", "hardcoded_secret", "high"),
    _d(_EFI, 34, "모바일 인증경계", "화면 강제실행에 의한 인증단계 우회", "Intent·URL Scheme·Cycript 또는 인증 파일 변조로 인증 화면을 건너뛰고 서비스를 이용할 수 있는지 확인한다.", "hybrid", "forced_screen", "high", ("navigation", "deep_link", "authorization"), "high"),
    _d(_EFI, 35, "거래·권한", "크로스사이트 요청변조 (CSRF)", "공격자가 만든 요청으로 로그인 이용자의 권한을 도용해 상태 변경이 가능한지 확인한다.", "manual", "manual", "high", "csrf", "high"),
    _d(_EFI, 36, "정보 노출", "디렉토리 목록 노출", "디렉터리 URL 요청 시 하위 파일과 디렉터리 목록이 노출되는지 확인한다.", "manual", "network_review", "medium", "directory_listing"),
    _d(_EFI, 37, "세션·전송", "서버 인증서 무결성 검증", "만료·호스트 불일치·신뢰되지 않은 자체서명 인증서를 앱이 허용하는지 확인한다.", "hybrid", "network_review", "medium", "certificate_validation", "high"),
    _d(_EFI, 38, "정보 노출", "시스템 운영정보 노출 여부", "응답·오류·소스에서 서버 버전·절대경로·중요 운영정보가 노출되는지 확인한다.", "hybrid", "network_review", "low", "system_information_exposure", "medium"),
    _d(_EFI, 39, "인증·인가", "인증 오류 횟수 제한기능 제공 여부", "정해진 오류 횟수 이상 인증 실패 후 계정·인증수단이 제한되는지 확인한다.", "manual", "manual", "blocked", "authentication_rate_limit", "high"),
    _d(_EFI, 40, "세션·전송", "불충분한 세션종료 처리", "로그아웃 후 세션이 파기되고 유휴 세션이 적절한 시간 안에 만료되는지 확인한다.", "manual", "network_review", "medium", "session_management", "high"),
    _d(_EFI, 41, "세션·전송", "취약한 HTTPS 프로토콜 이용", "SSL 3.0 이하 또는 TLS 1.2 미만 등 취약한 프로토콜을 서버가 허용하는지 확인한다.", "manual", "network_review", "medium", "weak_tls_protocol", "high"),
    _d(_EFI, 42, "세션·전송", "취약한 HTTPS 암호 알고리즘 이용", "RC4 등 취약 판정 암호군과 보안 강도가 부족한 HTTPS 암호 알고리즘을 허용하는지 확인한다.", "manual", "network_review", "medium", "weak_tls_cipher", "high"),
    _d(_EFI, 43, "세션·전송", "취약한 HTTPS 컴포넌트 사용", "Heartbleed·CCS Injection·POODLE·FREAK 등 알려진 HTTPS 컴포넌트 취약점이 존재하는지 확인한다.", "manual", "manual", "high", "vulnerable_tls_component", "critical"),
    _d(_EFI, 44, "세션·전송", "취약한 HTTPS 재협상 허용", "클라이언트 시작 비보안 TLS 재협상을 서버가 허용하는지 확인한다.", "manual", "network_review", "medium", "insecure_tls_renegotiation", "high"),
    _d(_EFI, 45, "노출 서비스", "불필요한 웹 메서드 허용", "사용하지 않는 HTTP 메서드로 파일 생성·변경·삭제 등 임의 동작이 가능한지 확인한다.", "manual", "manual", "blocked", "unsafe_http_method", "high"),
    _d(_EFI, 46, "노출 서비스", "관리자 페이지 노출 여부", "유추 가능한 경로·관리 포트에서 관리자 화면이 노출되고 접근통제가 우회되는지 확인한다.", "manual", "network_review", "medium", "admin_page_exposure"),
    _d(_EFI, 47, "정보 노출", "불필요한 파일 노출 여부", "샘플·테스트·백업·이전 소스 등 불필요한 파일이 알려진 경로에 노출되는지 확인한다.", "manual", "network_review", "medium", "unnecessary_file_exposure"),
    _d(_EFI, 48, "입력값·서버 실행", "크로스 사이트 스크립팅 (XSS)", "저장되거나 반사된 입력 스크립트가 다른 이용자의 브라우저·WebView에서 실행되는지 확인한다.", "manual", "manual", "high", "xss", "high"),
    _d(_EFI, 49, "단말 중요정보", "디버그 로그 내 중요정보 노출 여부", "단말 디버그 로그에 개인정보·고유식별정보·비밀번호·금융정보가 기록되는지 확인한다.", "dynamic", "runtime_logs", "low", "runtime_log_exposure", "high"),
    _d(_EFI, 50, "단말 중요정보", "백그라운드 화면 보호", "민감 화면을 백그라운드로 전환했을 때 최근 화면과 스냅샷 파일에 중요정보가 남는지 확인한다.", "manual", "ui_review", "medium", "background_screen", "high"),
    _d(_EFI, 51, "입력값·서버 실행", "서버 사이드 요청 위조 (SSRF)", "URL·IP 입력값 변조로 서버가 내부망이나 로컬 자원에 요청하고 응답을 반환하는지 확인한다.", "manual", "manual", "high", "ssrf", "high"),
    _d(_EFI, 52, "세션·전송", "세션정보 재사용", "탈취한 세션·OAuth·SSO 토큰을 다른 IP·단말에서 재사용해 권한 페이지에 접근 가능한지 확인한다.", "manual", "manual", "high", "session_reuse", "critical"),
    _d(_EFI, 53, "전자금융 인증", "인증수단 소유자 검증 여부", "타인 명의 인증서·전화번호·계좌·OTP를 등록하거나 인증에 사용 가능한지 확인한다.", "manual", "manual", "blocked", "credential_ownership", "critical"),
    _d(_EFI, 54, "모바일 인증경계", "모바일 DeepLink 도용 취약점", "조작한 Custom Scheme·Intent로 인증 우회·임의 리다이렉트·WebView·내부 파일 기능을 실행할 수 있는지 확인한다.", "hybrid", "deep_link", "high", ("deep_link", "navigation", "authorization"), "high"),
    _d(_EFI, 55, "세션·전송", "통신구간 암호화 적용 여부", "앱 통신에 TLS가 적용되고 취약 프로토콜·암호군·컴포넌트·재협상이 차단되는지 확인한다.", "dynamic", "network_plaintext", "medium", "network_sensitive_exposure", "critical"),
    _d(_EFI, 56, "입력값·서버 실행", "서버 사이드 템플릿 인젝션(SSTI)", "템플릿 표현식을 입력해 서버 측 계산·파일 읽기·명령 실행이 가능한지 확인한다.", "manual", "manual", "high", "ssti", "critical"),
)


STANDARD_CONTROLS: tuple[StandardControlDefinition, ...] = (
    *CRITICAL_INFRASTRUCTURE_CONTROLS,
    *ELECTRONIC_FINANCIAL_CONTROLS,
)


def controls_for_profile(profile: str) -> tuple[StandardControlDefinition, ...]:
    if profile == CRITICAL_INFRASTRUCTURE:
        return CRITICAL_INFRASTRUCTURE_CONTROLS
    if profile == ELECTRONIC_FINANCIAL:
        return ELECTRONIC_FINANCIAL_CONTROLS
    raise ValueError("지원하지 않는 국내 진단 기준 프로파일입니다.")


def control_by_id(profile: str, control_id: str) -> StandardControlDefinition | None:
    return next(
        (
            item
            for item in controls_for_profile(profile)
            if item.control_id == control_id
        ),
        None,
    )


def evaluate_profile_baseline(
    profile: str,
    platform: str,
) -> list[dict[str, Any]]:
    evaluated: list[dict[str, Any]] = []
    for definition in controls_for_profile(profile):
        if definition.automation == "static":
            status = "completed"
            result = "needs_review"
            summary = "정적 분석 결과를 수집했습니다. 문서 기준에 따른 동적 또는 전문가 검토 전에는 취약점을 확정하지 않습니다."
        elif definition.automation == "hybrid":
            status = "manual_required"
            result = "not_tested"
            summary = "정적 신호와 Live 동적 증적을 함께 확인해야 합니다."
        else:
            status = "manual_required"
            result = "not_tested"
            summary = "Live Run에서 문서의 진단 기준과 승인 범위에 따라 실행해야 합니다."
        item = definition.to_dict()
        item.update(
            {
                "platform": platform,
                "status": status,
                "result": result,
                "summary": summary,
            }
        )
        evaluated.append(item)
    return evaluated
