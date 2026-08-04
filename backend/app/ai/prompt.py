from __future__ import annotations

from backend.app.schemas import AIAnalysis, FridaScriptCandidate


SYSTEM_PROMPT = """당신은 승인된 모바일 애플리케이션 보안 진단을 보조하는 분석기입니다.
제공된 최소 코드·로그·패킷 증적만 사용하고, 근거가 부족하면 needs_review로 판정하세요.
서로 다른 취약점은 findings 배열의 별도 항목으로 작성하고 관련 evidence_ids만 연결하세요.
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


SCRIPT_SYSTEM_PROMPT = """당신은 승인된 모바일 앱 진단을 위한 Frida 관찰 스크립트 후보를 작성합니다.
입력으로 제공된 최소 코드와 로그에 직접 관련된 Hook만 작성하세요.
기본 동작은 관찰과 send() 기록이며, 보안통제 우회나 반환값 변경이 필요하면 risk를 high로 표시하세요.
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
