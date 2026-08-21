from __future__ import annotations

from backend.app.schemas import AIAnalysis, FridaScriptCandidate, NavigationRanking


SYSTEM_PROMPT = """당신은 승인된 모바일 애플리케이션 보안 진단을 보조하는 분석기입니다.
제공된 최소 코드·로그·패킷 증적만 사용하고, 근거가 부족하면 needs_review로 판정하세요.
서로 다른 취약점은 findings 배열의 별도 항목으로 작성하고 관련 evidence_ids만 연결하세요.
assessment_controls가 제공되면 각 Finding의 control_ids에는 입력에 있는 정확한 국내 기준 ID만 넣으세요.
기준 매핑이 불확실하면 control_ids를 비우고, AI 추론만으로 취약점을 confirmed로 판정하지 마세요.
심각도는 critical, high, medium, low, info 중 하나로 작성하세요.
추측을 사실처럼 쓰지 마세요. confidence는 0과 1 사이입니다.
응답은 지정된 JSON Schema만 따르며 Markdown을 출력하지 마세요."""


def build_prompt(task: str, context_text: str) -> str:
    schema = AIAnalysis.model_json_schema()
    return (
        f"작업: {task}\n\n"
        f"입력 증적:\n{context_text}\n\n"
        f"반드시 다음 JSON Schema에 맞는 JSON 객체만 반환하세요:\n{schema}"
    )


SCRIPT_SYSTEM_PROMPT = """당신은 승인된 모바일 앱 진단을 위한 Frida 스크립트 후보를 작성합니다.
입력으로 제공된 최소 코드와 로그에 직접 관련된 Hook만 작성하세요.
기본 동작은 관찰과 send() 기록이며, 보안통제 우회나 반환값 변경이 필요하면 risk를 high로 표시하세요.
security_bypass 목적이면 승인된 대상 앱 프로세스 안에서 루팅·탈옥 탐지 신호만 최소한으로 우회하고 risk를 high로 표시하세요.
네트워크 전송, 파일 삭제, 자격증명 수집, 지속성 확보 코드는 만들지 마세요.
생성물은 자동 실행되지 않고 구문 검사와 사용자 승인을 거칩니다.
응답은 지정된 JSON Schema의 JSON 객체만 반환하고 Markdown을 출력하지 마세요."""


def build_script_prompt(task: str, context_text: str) -> str:
    schema = FridaScriptCandidate.model_json_schema()
    return (
        f"작업: {task}\n\n"
        f"입력 증적:\n{context_text}\n\n"
        "후보 스크립트에는 대상 클래스/함수가 존재하지 않을 때 조용히 건너뛰는 예외 처리를 넣으세요.\n"
        f"반드시 다음 JSON Schema에 맞는 JSON 객체만 반환하세요:\n{schema}"
    )


NAVIGATION_RANKING_SYSTEM_PROMPT = """당신은 승인된 모바일 앱 취약점 진단의 안전 UI 탐색 순서를 보조합니다.
입력 navigation_candidates에 있는 정확한 candidate_id만 사용할 수 있습니다.
인증·세션·보안 설정·로컬 저장소·네트워크 동작을 관찰할 가능성이 높은 화면 이동을 우선하세요.
위험도 변경, 새 동작 생성, 클릭 승인, 취약점 판정은 수행하지 마세요.
priority_score는 증적 수집 기대 순서를 나타낼 뿐 안전성이나 취약 여부를 뜻하지 않습니다.
응답은 지정된 JSON Schema만 따르며 Markdown을 출력하지 마세요."""


def build_navigation_ranking_prompt(task: str, context_text: str) -> str:
    schema = NavigationRanking.model_json_schema()
    return (
        f"작업: {task}\n\n"
        f"입력 화면 후보:\n{context_text}\n\n"
        "입력에 없는 candidate_id는 절대 만들지 마세요. 모든 후보를 한 번씩만 반환하세요.\n"
        f"반드시 다음 JSON Schema에 맞는 JSON 객체만 반환하세요:\n{schema}"
    )
