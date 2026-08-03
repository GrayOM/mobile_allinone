from __future__ import annotations

from typing import Any

from backend.app.ai.base import AIProviderResult, AIScriptResult
from backend.app.ai.claude import ClaudeAIProvider
from backend.app.ai.nvidia import NvidiaAIProvider
from backend.app.core.config import AppSettings, get_settings
from backend.app.core.status import CapabilityStatus


class AIProviderChain:
    def __init__(
        self,
        nvidia: NvidiaAIProvider | None = None,
        claude: ClaudeAIProvider | None = None,
        settings: AppSettings | None = None,
    ):
        self.settings = settings or get_settings()
        self.nvidia = nvidia or NvidiaAIProvider(self.settings)
        self.claude = claude or ClaudeAIProvider(self.settings)

    async def analyze(
        self, task: str, context: dict[str, Any], *, masked: bool = True
    ) -> tuple[AIProviderResult, list[AIProviderResult]]:
        attempts: list[AIProviderResult] = []
        primary = await self.nvidia.analyze(task, context, masked=masked)
        attempts.append(primary)
        if (
            primary.status == CapabilityStatus.AVAILABLE
            and (primary.quality_score or 0) >= self.settings.ai_min_quality
        ):
            return primary, attempts

        fallback = await self.claude.analyze(task, context, masked=masked)
        attempts.append(fallback)
        if fallback.status == CapabilityStatus.AVAILABLE:
            fallback.fallback_reason = (
                primary.fallback_reason
                or f"primary_quality_below_{self.settings.ai_min_quality}"
            )
            return fallback, attempts
        return fallback, attempts

    async def generate_frida_script(
        self, task: str, context: dict[str, Any], *, masked: bool = True
    ) -> tuple[AIScriptResult, list[AIScriptResult]]:
        attempts: list[AIScriptResult] = []
        primary = await self.nvidia.generate_frida_script(
            task, context, masked=masked
        )
        attempts.append(primary)
        if (
            primary.status == CapabilityStatus.AVAILABLE
            and (primary.quality_score or 0) >= self.settings.ai_min_quality
        ):
            return primary, attempts
        fallback = await self.claude.generate_frida_script(
            task, context, masked=masked
        )
        attempts.append(fallback)
        if fallback.status == CapabilityStatus.AVAILABLE:
            fallback.fallback_reason = (
                primary.fallback_reason
                or f"primary_quality_below_{self.settings.ai_min_quality}"
            )
        return fallback, attempts
