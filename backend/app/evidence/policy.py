from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from backend.app.database.models import Evidence
from backend.app.navigation.models import UIState


@dataclass(slots=True)
class FindingEvidenceDecision:
    effective_verdict: str
    selected_ids: list[str]
    missing_requirements: list[list[str]]
    explanation: str


class EvidencePolicyEngine:
    """Select relevant evidence and enforce category-specific confirmation gates."""

    CATEGORY_RULES: tuple[tuple[tuple[str, ...], tuple[tuple[str, ...], ...]], ...] = (
        (
            ("idor", "authorization", "access_control", "object_boundary"),
            (("network_capture",), ("network_test",)),
        ),
        (
            ("storage", "local_data", "sensitive_data_exposure"),
            (
                ("storage_snapshot", "storage_diff", "network_capture"),
                ("storage_diff", "network_test", "device_log"),
            ),
        ),
        (
            ("frida", "hook", "root_detection", "certificate_pinning", "anti_tamper"),
            (("frida_script", "frida_session"), ("screenshot", "device_log")),
        ),
        (
            ("navigation", "deep_link", "exported_component"),
            (("navigation_action",), ("screenshot", "ui_tree")),
        ),
    )
    GENERIC_RELEVANT = {
        "network_capture",
        "network_test",
        "device_log",
        "storage_snapshot",
        "storage_diff",
        "frida_script",
        "frida_session",
        "screenshot",
        "ui_tree",
        "navigation_action",
        "runtime_tool",
        "static_analysis",
    }

    @classmethod
    def requirements_for(cls, category: str) -> tuple[tuple[str, ...], ...]:
        normalized = category.casefold()
        for terms, requirements in cls.CATEGORY_RULES:
            if any(term in normalized for term in terms):
                return requirements
        return ((tuple(sorted(cls.GENERIC_RELEVANT))),)

    def decide_finding(
        self,
        *,
        category: str,
        requested_verdict: str,
        confidence: float,
        proposed_ids: Iterable[str],
        evidence_by_id: dict[str, Evidence],
        minimum_quality: float,
    ) -> FindingEvidenceDecision:
        requirements = self.requirements_for(category)
        relevant_types = {item for group in requirements for item in group}
        selected = []
        for evidence_id in proposed_ids:
            evidence = evidence_by_id.get(evidence_id)
            if (
                evidence
                and evidence.evidence_type in relevant_types
                and evidence_id not in selected
            ):
                selected.append(evidence_id)
        available_types = {
            evidence_by_id[item].evidence_type
            for item in selected
            if item in evidence_by_id
        }
        missing = [
            list(group)
            for group in requirements
            if not available_types.intersection(group)
        ]
        if not selected:
            verdict = "candidate"
            explanation = "현재 Run의 관련 증적이 없어 후보 상태로 제한했습니다."
        elif confidence < minimum_quality:
            verdict = "needs_review"
            explanation = "AI 품질 점수가 기준 미만이어서 검토가 필요합니다."
        elif requested_verdict == "confirmed" and missing:
            verdict = "needs_review"
            explanation = "Finding 유형별 confirmed 증적 기준을 충족하지 못했습니다."
        else:
            verdict = requested_verdict
            explanation = "제안 증적 중 Finding 범주와 관련된 항목만 연결했습니다."
        return FindingEvidenceDecision(verdict, selected, missing, explanation)

    @staticmethod
    def transition_triggers(
        before: UIState,
        after: UIState,
        *,
        event_signals: Iterable[str] = (),
    ) -> list[str]:
        triggers = []
        if before.activity != after.activity:
            triggers.append("activity_changed")
        if before.text_hash != after.text_hash:
            triggers.append("important_text_changed")
        if any("dialog" in item.class_name.casefold() for item in after.elements):
            triggers.append("dialog_appeared")
        allowed_signals = {
            "app_crash",
            "frida_detection",
            "network_request",
            "sensitive_data",
            "storage_change",
            "deep_link_result",
            "security_control_change",
            "api_validation",
            "reproduced_candidate",
        }
        triggers.extend(
            item for item in event_signals if item in allowed_signals and item not in triggers
        )
        return triggers
