from __future__ import annotations

import hashlib
import json

from .models import NetworkTestCandidate, PassiveFlowAnalysis


class NetworkCandidateEngine:
    """Generate proposals only; it never sends a request."""

    @staticmethod
    def _id(flow_id: str, test_type: str, modified: list[dict]) -> str:
        material = json.dumps(
            [flow_id, test_type, modified], sort_keys=True, ensure_ascii=False
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]

    def generate(
        self, analysis: PassiveFlowAnalysis
    ) -> list[NetworkTestCandidate]:
        candidates = [
            NetworkTestCandidate(
                id=self._id(analysis.source_flow_id, "passive_metadata", []),
                test_type="passive_metadata",
                source_flow_id=analysis.source_flow_id,
                method=analysis.method,
                endpoint=analysis.endpoint,
                modified_fields=[],
                expected_result="인증·Cookie·민감 응답 필드 구조를 로컬에서 분류합니다.",
                risk="low",
                requires_approval=False,
                auto_executable=True,
                rationale="요청을 전송하지 않는 로컬 분석입니다.",
                synthetic=analysis.synthetic,
            )
        ]
        if analysis.method in {"GET", "HEAD"}:
            candidates.append(
                NetworkTestCandidate(
                    id=self._id(analysis.source_flow_id, "read_only_replay", []),
                    test_type="read_only_replay",
                    source_flow_id=analysis.source_flow_id,
                    method=analysis.method,
                    endpoint=analysis.endpoint,
                    modified_fields=[],
                    expected_result="원본과 동일한 읽기 전용 응답 구조를 비교합니다.",
                    risk="low",
                    requires_approval=not analysis.synthetic,
                    auto_executable=analysis.synthetic,
                    rationale=(
                        "Mock에서는 합성 재현을 자동 실행합니다. Live 목적지는 별도 범위 승인 전 재전송하지 않습니다."
                    ),
                    synthetic=analysis.synthetic,
                )
            )
        else:
            modifications = [
                {
                    "location": "request",
                    "original": f"{analysis.method} {analysis.endpoint}",
                    "candidate": "exact replay",
                    "effect": "state change possible",
                }
            ]
            candidates.append(
                NetworkTestCandidate(
                    id=self._id(
                        analysis.source_flow_id, "state_changing_replay", modifications
                    ),
                    test_type="state_changing_replay",
                    source_flow_id=analysis.source_flow_id,
                    method=analysis.method,
                    endpoint=analysis.endpoint,
                    modified_fields=modifications,
                    expected_result="원본 상태 변경 요청의 재현 여부를 확인합니다.",
                    risk="high",
                    requires_approval=True,
                    auto_executable=False,
                    rationale="POST·PUT·PATCH·DELETE 및 업로드는 항상 1회 승인이 필요합니다.",
                    synthetic=analysis.synthetic,
                )
            )
        for item in analysis.object_id_candidates[:20]:
            modifications = [
                {
                    "location": item["location"],
                    "field": item["name"],
                    "original": item["masked_value"],
                    "candidate": "<approved-test-object-id-required>",
                    "effect": "authorization boundary",
                }
            ]
            candidates.append(
                NetworkTestCandidate(
                    id=self._id(analysis.source_flow_id, "object_boundary", modifications),
                    test_type="object_boundary",
                    source_flow_id=analysis.source_flow_id,
                    method=analysis.method,
                    endpoint=analysis.endpoint,
                    modified_fields=modifications,
                    expected_result="허가된 테스트 계정·데이터 범위의 Object만 비교합니다.",
                    risk="high",
                    requires_approval=True,
                    auto_executable=False,
                    rationale="다른 Object 접근 후보는 정확한 변경값과 범위 승인 없이는 실행하지 않습니다.",
                    synthetic=analysis.synthetic,
                )
            )
        return candidates
