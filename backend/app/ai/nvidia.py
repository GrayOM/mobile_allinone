from __future__ import annotations

import json
from typing import Any

import httpx
from pydantic import ValidationError

from backend.app.ai.base import AIProvider, AIProviderResult, AIScriptResult
from backend.app.ai.masking import mask_context
from backend.app.ai.prompt import (
    SCRIPT_SYSTEM_PROMPT,
    SYSTEM_PROMPT,
    build_prompt,
    build_script_prompt,
)
from backend.app.core.config import AppSettings, get_settings
from backend.app.core.status import CapabilityStatus
from backend.app.schemas import AIAnalysis, FridaScriptCandidate


class NvidiaAIProvider(AIProvider):
    name = "nvidia"

    def __init__(self, settings: AppSettings | None = None):
        self.settings = settings or get_settings()
        self.model = self.settings.nvidia_model

    async def analyze(
        self, task: str, context: dict[str, Any], *, masked: bool = True
    ) -> AIProviderResult:
        if context.get("simulate_nvidia_failure"):
            return AIProviderResult(
                CapabilityStatus.FAILED,
                self.name,
                self.model,
                "요청된 NVIDIA 장애 모의가 활성화되었습니다.",
                fallback_reason="simulated_failure",
                masked=masked,
            )
        if not self.settings.nvidia_api_key:
            return AIProviderResult(
                CapabilityStatus.NOT_CONFIGURED,
                self.name,
                self.model,
                "NVIDIA_API_KEY가 설정되지 않았습니다.",
                fallback_reason="missing_api_key",
                masked=masked,
            )
        context_text, _ = (
            mask_context(context)
            if masked
            else (json.dumps(context, ensure_ascii=False, default=str), [])
        )
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_prompt(task, context_text)},
            ],
            "temperature": 0.1,
            "max_tokens": 1800,
            "stream": False,
        }
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.post(
                    f"{self.settings.nvidia_base_url.rstrip('/')}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.settings.nvidia_api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
                response.raise_for_status()
                body = response.json()
            raw = body["choices"][0]["message"]["content"]
            parsed = self._parse(raw)
            return AIProviderResult(
                CapabilityStatus.AVAILABLE,
                self.name,
                self.model,
                "NVIDIA AI 분석을 완료했습니다.",
                analysis=parsed,
                raw_response=raw,
                quality_score=parsed.confidence,
                masked=masked,
            )
        except (httpx.HTTPError, KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            return AIProviderResult(
                CapabilityStatus.FAILED,
                self.name,
                self.model,
                f"NVIDIA 응답 처리 실패: {type(exc).__name__}: {exc}",
                raw_response=locals().get("raw"),
                fallback_reason=type(exc).__name__,
                masked=masked,
            )
        except ValidationError as exc:
            return AIProviderResult(
                CapabilityStatus.FAILED,
                self.name,
                self.model,
                f"NVIDIA JSON Schema 검증 실패: {exc}",
                raw_response=locals().get("raw"),
                fallback_reason="schema_validation_failed",
                masked=masked,
            )

    @staticmethod
    def _parse(raw: str) -> AIAnalysis:
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = re_fence(cleaned)
        return AIAnalysis.model_validate_json(cleaned)

    async def generate_frida_script(
        self, task: str, context: dict[str, Any], *, masked: bool = True
    ) -> AIScriptResult:
        if context.get("simulate_nvidia_failure"):
            return AIScriptResult(
                CapabilityStatus.FAILED,
                self.name,
                self.model,
                "요청된 NVIDIA 장애 모의가 활성화되었습니다.",
                fallback_reason="simulated_failure",
                masked=masked,
            )
        if not self.settings.nvidia_api_key:
            return AIScriptResult(
                CapabilityStatus.NOT_CONFIGURED,
                self.name,
                self.model,
                "NVIDIA_API_KEY가 설정되지 않았습니다.",
                fallback_reason="missing_api_key",
                masked=masked,
            )
        context_text, _ = (
            mask_context(context)
            if masked
            else (json.dumps(context, ensure_ascii=False, default=str), [])
        )
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SCRIPT_SYSTEM_PROMPT},
                {"role": "user", "content": build_script_prompt(task, context_text)},
            ],
            "temperature": 0.05,
            "max_tokens": 3000,
            "stream": False,
        }
        try:
            async with httpx.AsyncClient(timeout=75) as client:
                response = await client.post(
                    f"{self.settings.nvidia_base_url.rstrip('/')}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.settings.nvidia_api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
                response.raise_for_status()
                body = response.json()
            raw = body["choices"][0]["message"]["content"]
            candidate = FridaScriptCandidate.model_validate_json(re_fence(raw.strip()))
            return AIScriptResult(
                CapabilityStatus.AVAILABLE,
                self.name,
                self.model,
                "NVIDIA AI가 Frida 후보를 생성했습니다.",
                candidate=candidate,
                raw_response=raw,
                quality_score=candidate.confidence,
                masked=masked,
            )
        except ValidationError as exc:
            return AIScriptResult(
                CapabilityStatus.FAILED,
                self.name,
                self.model,
                f"NVIDIA 스크립트 JSON Schema 검증 실패: {exc}",
                raw_response=locals().get("raw"),
                fallback_reason="schema_validation_failed",
                masked=masked,
            )
        except (httpx.HTTPError, KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            return AIScriptResult(
                CapabilityStatus.FAILED,
                self.name,
                self.model,
                f"NVIDIA 스크립트 응답 처리 실패: {type(exc).__name__}: {exc}",
                raw_response=locals().get("raw"),
                fallback_reason=type(exc).__name__,
                masked=masked,
            )


def re_fence(value: str) -> str:
    lines = value.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines)
