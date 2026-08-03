from __future__ import annotations

import asyncio
from typing import Any

from backend.app.ai.base import AIProvider, AIProviderResult, AIScriptResult
from backend.app.core.status import CapabilityStatus
from backend.app.schemas import AIAnalysis, FridaScriptCandidate


class MockAIProvider(AIProvider):
    name = "mock"
    model = "mock-evidence-analyst-v1"

    async def analyze(
        self, task: str, context: dict[str, Any], *, masked: bool = True
    ) -> AIProviderResult:
        await asyncio.sleep(0.08)
        evidence_ids = [
            str(item)
            for item in context.get("evidence_ids", [])
            if isinstance(item, (str, int))
        ]
        analysis = AIAnalysis(
            title="인증 토큰이 프록시 응답에서 관찰됨",
            category="sensitive_data_exposure",
            platform=str(context.get("platform", "android")),
            location="POST /v1/session 응답 본문",
            verdict="needs_review",
            confidence=0.82,
            rationale=(
                "Mock 프록시 응답 본문에서 access_token 키가 확인되었습니다. "
                "전송 구간은 HTTPS이므로 취약점 확정 전에 로그·저장소 재노출 여부를 추가로 확인해야 합니다."
            ),
            reproduction=[
                "Mock 단말에서 대상 앱을 실행합니다.",
                "로그인 동작 후 /v1/session 응답을 확인합니다.",
                "동일 토큰이 로그 또는 로컬 저장소에 남는지 확인합니다.",
            ],
            evidence_ids=evidence_ids,
            false_positive_risk="데모 데이터이며 실제 자격증명이 아닙니다.",
            additional_checks=[
                "토큰 저장 위치 확인",
                "Logcat 토큰 노출 여부 확인",
                "세션 만료·폐기 정책 확인",
            ],
        )
        return AIProviderResult(
            CapabilityStatus.AVAILABLE,
            self.name,
            self.model,
            "Mock AI 분석을 완료했습니다.",
            analysis=analysis,
            raw_response=analysis.model_dump_json(),
            quality_score=analysis.confidence,
            masked=masked,
        )

    async def generate_frida_script(
        self, task: str, context: dict[str, Any], *, masked: bool = True
    ) -> AIScriptResult:
        await asyncio.sleep(0.05)
        platform = str(context.get("platform") or "android")
        candidate = FridaScriptCandidate(
            name=f"Mock {platform} 보안통제 관찰 후보",
            platform=platform,
            category=str(context.get("category") or "Custom"),
            target_framework=str(context.get("target_framework") or "generic"),
            conditions=["Java runtime available", "target class is loaded"],
            risk="low",
            content=(
                "setImmediate(function () {\n"
                "  try {\n"
                "    send({event: 'msw_ai_candidate_loaded', mode: 'observe_only'});\n"
                "  } catch (error) {\n"
                "    send({event: 'msw_ai_candidate_error', error: String(error)});\n"
                "  }\n"
                "});\n"
            ),
            rationale="Mock 모드에서 승인·구문 검사 흐름을 검증하는 관찰 전용 후보입니다.",
            confidence=0.78,
            safety_notes=[
                "반환값과 앱 상태를 변경하지 않습니다.",
                "사용자 승인 전에는 실행되지 않습니다.",
            ],
        )
        return AIScriptResult(
            CapabilityStatus.AVAILABLE,
            self.name,
            self.model,
            "Mock AI가 관찰 전용 Frida 후보를 생성했습니다.",
            candidate=candidate,
            raw_response=candidate.model_dump_json(),
            quality_score=candidate.confidence,
            masked=masked,
        )
