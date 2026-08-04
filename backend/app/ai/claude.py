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


class ClaudeAIProvider(AIProvider):
    name = "claude"

    def __init__(self, settings: AppSettings | None = None):
        self.settings = settings or get_settings()
        self.model = self.settings.claude_model

    async def analyze(
        self, task: str, context: dict[str, Any], *, masked: bool = True
    ) -> AIProviderResult:
        if not self.settings.claude_api_key:
            return AIProviderResult(
                CapabilityStatus.NOT_CONFIGURED,
                self.name,
                self.model,
                "ANTHROPIC_API_KEY가 설정되지 않았습니다.",
                fallback_reason="missing_api_key",
                masked=masked,
            )
        context_text, _ = (
            mask_context(context, self.settings.ai_sensitive_keys)
            if masked
            else (json.dumps(context, ensure_ascii=False, default=str), [])
        )
        payload = {
            "model": self.model,
            "max_tokens": 1800,
            "temperature": 0.1,
            "system": SYSTEM_PROMPT,
            "messages": [
                {"role": "user", "content": build_prompt(task, context_text)}
            ],
            "output_config": {
                "format": {
                    "type": "json_schema",
                    "schema": AIAnalysis.model_json_schema(),
                }
            },
        }
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.post(
                    f"{self.settings.claude_base_url.rstrip('/')}/messages",
                    headers={
                        "x-api-key": self.settings.claude_api_key,
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
                response.raise_for_status()
                body = response.json()
            raw = next(
                block["text"] for block in body["content"] if block.get("type") == "text"
            )
            parsed = AIAnalysis.model_validate_json(raw)
            return AIProviderResult(
                CapabilityStatus.AVAILABLE,
                self.name,
                self.model,
                "Claude AI 분석을 완료했습니다.",
                analysis=parsed,
                raw_response=raw,
                quality_score=parsed.confidence,
                masked=masked,
            )
        except (httpx.HTTPError, KeyError, StopIteration, TypeError, json.JSONDecodeError) as exc:
            return AIProviderResult(
                CapabilityStatus.FAILED,
                self.name,
                self.model,
                f"Claude 응답 처리 실패: {type(exc).__name__}: {exc}",
                raw_response=locals().get("raw"),
                fallback_reason=type(exc).__name__,
                masked=masked,
            )
        except ValidationError as exc:
            return AIProviderResult(
                CapabilityStatus.FAILED,
                self.name,
                self.model,
                f"Claude JSON Schema 검증 실패: {exc}",
                raw_response=locals().get("raw"),
                fallback_reason="schema_validation_failed",
                masked=masked,
            )

    async def generate_frida_script(
        self, task: str, context: dict[str, Any], *, masked: bool = True
    ) -> AIScriptResult:
        if not self.settings.claude_api_key:
            return AIScriptResult(
                CapabilityStatus.NOT_CONFIGURED,
                self.name,
                self.model,
                "ANTHROPIC_API_KEY가 설정되지 않았습니다.",
                fallback_reason="missing_api_key",
                masked=masked,
            )
        context_text, _ = (
            mask_context(context, self.settings.ai_sensitive_keys)
            if masked
            else (json.dumps(context, ensure_ascii=False, default=str), [])
        )
        payload = {
            "model": self.model,
            "max_tokens": 3000,
            "temperature": 0.05,
            "system": SCRIPT_SYSTEM_PROMPT,
            "messages": [
                {"role": "user", "content": build_script_prompt(task, context_text)}
            ],
            "output_config": {
                "format": {
                    "type": "json_schema",
                    "schema": FridaScriptCandidate.model_json_schema(),
                }
            },
        }
        try:
            async with httpx.AsyncClient(timeout=75) as client:
                response = await client.post(
                    f"{self.settings.claude_base_url.rstrip('/')}/messages",
                    headers={
                        "x-api-key": self.settings.claude_api_key,
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
                response.raise_for_status()
                body = response.json()
            raw = next(
                block["text"] for block in body["content"] if block.get("type") == "text"
            )
            candidate = FridaScriptCandidate.model_validate_json(raw)
            return AIScriptResult(
                CapabilityStatus.AVAILABLE,
                self.name,
                self.model,
                "Claude AI가 Frida 후보를 생성했습니다.",
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
                f"Claude 스크립트 JSON Schema 검증 실패: {exc}",
                raw_response=locals().get("raw"),
                fallback_reason="schema_validation_failed",
                masked=masked,
            )
        except (httpx.HTTPError, KeyError, StopIteration, TypeError, json.JSONDecodeError) as exc:
            return AIScriptResult(
                CapabilityStatus.FAILED,
                self.name,
                self.model,
                f"Claude 스크립트 응답 처리 실패: {type(exc).__name__}: {exc}",
                raw_response=locals().get("raw"),
                fallback_reason=type(exc).__name__,
                masked=masked,
            )
