from __future__ import annotations

import asyncio
from typing import Any

from backend.app.ai.base import (
    AINavigationRankingResult,
    AIProvider,
    AIProviderResult,
    AIScriptResult,
)
from backend.app.core.status import CapabilityStatus
from backend.app.schemas import (
    AIAnalysis,
    AIFindingCandidate,
    FridaScriptCandidate,
    NavigationCandidateRanking,
    NavigationRanking,
)


class MockAIProvider(AIProvider):
    name = "mock"
    model = "mock-evidence-analyst-v1"

    async def analyze(
        self, task: str, context: dict[str, Any], *, masked: bool = True
    ) -> AIProviderResult:
        await asyncio.sleep(0.08)
        evidence_ids = [
            str(item["id"])
            for item in context.get("evidence_catalog", [])
            if isinstance(item, dict)
            and item.get("id")
            and item.get("type") in {"network_capture", "device_log"}
        ]
        control_ids = [
            str(item["control_id"])
            for item in context.get("assessment_controls", [])
            if isinstance(item, dict)
            and item.get("control_id")
            and "sensitive_data_exposure" in item.get("finding_categories", [])
        ][:3]
        finding = AIFindingCandidate(
            title="인증 토큰이 프록시 응답에서 관찰됨",
            category="sensitive_data_exposure",
            platform=str(context.get("platform", "android")),
            severity="medium",
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
            control_ids=control_ids,
        )
        analysis = AIAnalysis(findings=[finding])
        return AIProviderResult(
            CapabilityStatus.AVAILABLE,
            self.name,
            self.model,
            "Mock AI 분석을 완료했습니다.",
            analysis=analysis,
            raw_response=analysis.model_dump_json(),
            quality_score=finding.confidence,
            masked=masked,
            synthetic=True,
        )

    async def generate_frida_script(
        self, task: str, context: dict[str, Any], *, masked: bool = True
    ) -> AIScriptResult:
        await asyncio.sleep(0.05)
        platform = str(context.get("platform") or "android")
        security_bypass = context.get("purpose") == "security_bypass"
        candidate = FridaScriptCandidate(
            name=(
                f"Mock {platform} 루팅·탈옥 탐지 우회 후보"
                if security_bypass
                else f"Mock {platform} 보안통제 관찰 후보"
            ),
            platform=platform,
            category=str(context.get("category") or "Custom"),
            target_framework=str(context.get("target_framework") or "generic"),
            conditions=["Java runtime available", "target class is loaded"],
            risk="high" if security_bypass else "low",
            content=(
                "setImmediate(function () {\n"
                "  try {\n"
                "    send({event: 'msw_ai_candidate_loaded', mode: 'observe_only'});\n"
                "  } catch (error) {\n"
                "    send({event: 'msw_ai_candidate_error', error: String(error)});\n"
                "  }\n"
                "});\n"
            ),
            rationale=(
                "Mock 모드에서 고위험 우회 후보의 분석·승인·구문 검사 흐름을 검증합니다."
                if security_bypass
                else "Mock 모드에서 승인·구문 검사 흐름을 검증하는 관찰 전용 후보입니다."
            ),
            confidence=0.78,
            safety_notes=[
                (
                    "실제 단말에는 적용되지 않는 합성 후보이며 실행 전 전체 코드 검토가 필요합니다."
                    if security_bypass
                    else "반환값과 앱 상태를 변경하지 않습니다."
                ),
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
            synthetic=True,
        )

    async def rank_navigation_candidates(
        self, task: str, context: dict[str, Any], *, masked: bool = True
    ) -> AINavigationRankingResult:
        del task
        await asyncio.sleep(0.03)
        candidates = [
            item
            for item in context.get("navigation_candidates", [])
            if isinstance(item, dict) and item.get("candidate_id")
        ]
        security_terms = {
            "계정": 24,
            "보안": 30,
            "인증": 30,
            "인증서": 28,
            "프로필": 20,
            "로그인": 30,
            "session": 30,
            "security": 30,
            "account": 24,
            "profile": 20,
            "certificate": 28,
        }
        rankings: list[NavigationCandidateRanking] = []
        for index, item in enumerate(candidates):
            label = f"{item.get('label', '')} {item.get('resource_hint', '')}".casefold()
            bonus = max(
                (points for term, points in security_terms.items() if term in label),
                default=0,
            )
            score = min(100, 50 + bonus - index)
            rankings.append(
                NavigationCandidateRanking(
                    candidate_id=str(item["candidate_id"]),
                    priority_score=score,
                    confidence=0.84 if bonus else 0.68,
                    rationale=(
                        "보안·인증 관련 화면에서 취약 증적 신호를 관찰할 가능성이 높습니다."
                        if bonus
                        else "안전 후보 중 화면 커버리지 확대 가능성을 기준으로 정렬했습니다."
                    ),
                )
            )
        rankings.sort(key=lambda item: (-item.priority_score, item.candidate_id))
        ranking = NavigationRanking(rankings=rankings)
        return AINavigationRankingResult(
            CapabilityStatus.AVAILABLE,
            self.name,
            self.model,
            "Mock AI가 로컬 안전 후보의 탐색 순서를 제안했습니다.",
            ranking=ranking,
            raw_response=ranking.model_dump_json(),
            quality_score=ranking.confidence,
            masked=masked,
            synthetic=True,
        )
