from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from typing import Any

from backend.app.core.status import CapabilityStatus
from backend.app.schemas import AIAnalysis, FridaScriptCandidate


@dataclass(slots=True)
class AIProviderResult:
    status: CapabilityStatus
    provider: str
    model: str
    message: str
    analysis: AIAnalysis | None = None
    raw_response: str | None = None
    quality_score: float | None = None
    masked: bool = True
    fallback_reason: str | None = None
    synthetic: bool = False

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["status"] = self.status.value
        if self.analysis:
            result["analysis"] = self.analysis.model_dump()
        return result


@dataclass(slots=True)
class AIScriptResult:
    status: CapabilityStatus
    provider: str
    model: str
    message: str
    candidate: FridaScriptCandidate | None = None
    raw_response: str | None = None
    quality_score: float | None = None
    masked: bool = True
    fallback_reason: str | None = None
    synthetic: bool = False

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["status"] = self.status.value
        if self.candidate:
            result["candidate"] = self.candidate.model_dump()
        return result


class AIProvider(ABC):
    name: str
    model: str

    @abstractmethod
    async def analyze(
        self, task: str, context: dict[str, Any], *, masked: bool = True
    ) -> AIProviderResult:
        raise NotImplementedError

    async def generate_frida_script(
        self, task: str, context: dict[str, Any], *, masked: bool = True
    ) -> AIScriptResult:
        return AIScriptResult(
            CapabilityStatus.UNSUPPORTED,
            self.name,
            self.model,
            "이 AI Provider는 Frida 스크립트 생성을 지원하지 않습니다.",
            masked=masked,
        )
