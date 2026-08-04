from __future__ import annotations

from typing import Any

import pytest

from backend.app.ai.base import AIProvider, AIProviderResult
from backend.app.ai.chain import AIProviderChain
from backend.app.core.config import AppSettings
from backend.app.core.status import CapabilityStatus
from backend.app.schemas import AIAnalysis, AIFindingCandidate


class FailingNvidia(AIProvider):
    name = "nvidia"
    model = "test-primary"

    async def analyze(
        self, task: str, context: dict[str, Any], *, masked: bool = True
    ) -> AIProviderResult:
        return AIProviderResult(
            CapabilityStatus.FAILED,
            self.name,
            self.model,
            "rate limit",
            fallback_reason="rate_limit",
        )


class SuccessfulClaude(AIProvider):
    name = "claude"
    model = "test-fallback"

    async def analyze(
        self, task: str, context: dict[str, Any], *, masked: bool = True
    ) -> AIProviderResult:
        analysis = AIAnalysis(
            findings=[
                AIFindingCandidate(
                    title="Fallback result",
                    category="test",
                    platform="android",
                    severity="medium",
                    location="test",
                    verdict="needs_review",
                    confidence=0.9,
                    rationale="validated fallback",
                    reproduction=["one"],
                    evidence_ids=[],
                    false_positive_risk="none",
                    additional_checks=[],
                )
            ]
        )
        return AIProviderResult(
            CapabilityStatus.AVAILABLE,
            self.name,
            self.model,
            "ok",
            analysis=analysis,
            quality_score=0.9,
        )


@pytest.mark.asyncio
async def test_nvidia_failure_falls_back_to_claude():
    chain = AIProviderChain(
        nvidia=FailingNvidia(),  # type: ignore[arg-type]
        claude=SuccessfulClaude(),  # type: ignore[arg-type]
        settings=AppSettings(),
    )

    selected, attempts = await chain.analyze("test", {"secret": "masked"})

    assert [attempt.provider for attempt in attempts] == ["nvidia", "claude"]
    assert selected.provider == "claude"
    assert selected.status == CapabilityStatus.AVAILABLE
    assert selected.fallback_reason == "rate_limit"
