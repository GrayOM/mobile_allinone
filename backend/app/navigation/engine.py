from __future__ import annotations

import asyncio
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Awaitable, Callable

from backend.app.core.status import CapabilityStatus
from backend.app.devices.base import DeviceOperation

from .base import UIDriver
from .approval import normalized_navigation_candidate
from .models import (
    NavigationAction,
    NavigationCandidate,
    NavigationLimits,
    NavigationResult,
    UIState,
)
from .policy import NavigationRiskPolicy


BeforeHook = Callable[[int, UIState, NavigationCandidate], Awaitable[list[str]]]
AfterHook = Callable[
    [int, UIState, NavigationCandidate, DeviceOperation, UIState | None, list[str]],
    Awaitable[list[str]],
]
UpdateHook = Callable[[dict[str, object]], Awaitable[None]]


@dataclass(slots=True)
class NavigationHooks:
    before_action: BeforeHook | None = None
    after_action: AfterHook | None = None
    on_update: UpdateHook | None = None


class NavigationEngine:
    """Bounded DFS explorer with local candidate and risk enforcement."""

    def __init__(
        self,
        driver: UIDriver,
        *,
        target_package: str,
        limits: NavigationLimits | None = None,
        policy: NavigationRiskPolicy | None = None,
        hooks: NavigationHooks | None = None,
        synthetic: bool = False,
    ):
        self.driver = driver
        self.target_package = target_package
        self.limits = limits or NavigationLimits()
        self.policy = policy or NavigationRiskPolicy()
        self.hooks = hooks or NavigationHooks()
        self.synthetic = synthetic
        self._states: dict[str, UIState] = {}
        self._actions: list[NavigationAction] = []
        self._pending: dict[tuple[str, str], dict[str, object]] = {}
        self._visits: Counter[str] = Counter()
        self._attempted: set[tuple[str, str]] = set()
        self._interaction_variants: dict[str, set[str]] = defaultdict(set)
        self._scroll_counts: Counter[str] = Counter()
        self._seen_scroll_views: set[tuple[str, str]] = set()
        self._deadline = 0.0
        self._termination_reason = "exhausted"

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _limit_reached(self) -> bool:
        if len(self._actions) >= self.limits.max_actions:
            self._termination_reason = "max_actions"
            return True
        if asyncio.get_running_loop().time() >= self._deadline:
            self._termination_reason = "timeout"
            return True
        return False

    async def _update(self, event: str, **data: object) -> None:
        if self.hooks.on_update:
            await self.hooks.on_update(
                {
                    "event": event,
                    "state_count": len(self._states),
                    "action_count": len(self._actions),
                    "pending_count": len(self._pending),
                    **data,
                }
            )

    def _add_state(self, state: UIState) -> bool:
        self._visits[state.fingerprint] += 1
        if state.fingerprint in self._states:
            return True
        variants = self._interaction_variants[state.structural_fingerprint]
        if (
            state.interaction_fingerprint not in variants
            and len(variants)
            >= self.limits.max_interaction_variants_per_structure
        ):
            self._termination_reason = "max_interaction_variants_per_structure"
            return False
        if len(self._states) >= self.limits.max_states:
            self._termination_reason = "max_states"
            return False
        variants.add(state.interaction_fingerprint)
        self._states[state.fingerprint] = state
        return True

    async def _queue_risky(
        self, state: UIState, candidate: NavigationCandidate
    ) -> None:
        key = (state.fingerprint, candidate.element_id)
        pending = normalized_navigation_candidate(
            {
                **candidate.to_dict(),
                "state_fingerprint": state.fingerprint,
                "package": state.package,
                "activity": state.activity,
                "status": "pending_approval",
                "queued_at": self._now(),
            }
        )
        if key in self._pending:
            return
        self._pending[key] = pending
        await self._update(
            "pending",
            candidate=pending,
            state=state.to_dict(include_elements=False),
        )

    async def _execute(
        self, state: UIState, candidate: NavigationCandidate
    ) -> tuple[NavigationAction, UIState | None]:
        sequence = len(self._actions) + 1
        before_evidence: list[str] = []
        if self.hooks.before_action:
            before_evidence = await self.hooks.before_action(sequence, state, candidate)

        live_state = await asyncio.wait_for(
            self.driver.dump_ui(), timeout=self.limits.action_timeout
        )
        live_element = live_state.element(candidate.element_id)
        operation: DeviceOperation
        after_state: UIState | None = None
        if live_state.fingerprint != state.fingerprint or not live_element:
            operation = DeviceOperation(
                CapabilityStatus.FAILED,
                "실행 직전 UI Tree가 변경되어 stale action을 차단했습니다.",
                synthetic=self.synthetic,
            )
        else:
            rechecked = self.policy.classify(live_element, self.target_package)
            if rechecked.requires_approval or rechecked.risk != "low":
                operation = DeviceOperation(
                    CapabilityStatus.MANUAL_REQUIRED,
                    "실행 직전 위험 정책 재검증에서 자동 동작을 차단했습니다.",
                    synthetic=self.synthetic,
                )
                await self._queue_risky(live_state, rechecked)
            else:
                x, y = live_element.bounds.center
                try:
                    operation = await asyncio.wait_for(
                        self.driver.tap(x, y), timeout=self.limits.action_timeout
                    )
                    if operation.status == CapabilityStatus.AVAILABLE:
                        after_state = await asyncio.wait_for(
                            self.driver.wait_for_idle(self.limits.action_timeout),
                            timeout=self.limits.action_timeout + 0.5,
                        )
                except asyncio.TimeoutError:
                    operation = DeviceOperation(
                        CapabilityStatus.FAILED,
                        "UI action timeout을 초과했습니다.",
                        synthetic=self.synthetic,
                    )

        evidence_ids = list(before_evidence)
        if self.hooks.after_action:
            evidence_ids.extend(
                await self.hooks.after_action(
                    sequence,
                    state,
                    candidate,
                    operation,
                    after_state,
                    list(before_evidence),
                )
            )
        action = NavigationAction(
            sequence=sequence,
            action_type=candidate.action_type,
            element_id=candidate.element_id or None,
            label=candidate.label,
            risk=candidate.risk,
            source_state=state.fingerprint,
            destination_state=after_state.fingerprint if after_state else None,
            result=operation.status.value,
            message=operation.message,
            timestamp=self._now(),
            evidence_ids=list(dict.fromkeys(evidence_ids)),
            command=operation.command,
            synthetic=bool(operation.synthetic or self.synthetic),
        )
        self._actions.append(action)
        await self._update("action", action=action.to_dict())
        return action, after_state

    async def _execute_back(self, state: UIState) -> UIState | None:
        if self._limit_reached():
            return None
        candidate = NavigationCandidate(
            action_type="back",
            element_id="",
            label="뒤로 이동",
            risk="low",
            rationale="탐색 경로를 복원하는 결정론적 시스템 동작입니다.",
        )
        sequence = len(self._actions) + 1
        before_evidence: list[str] = []
        if self.hooks.before_action:
            before_evidence = await self.hooks.before_action(sequence, state, candidate)
        try:
            operation = await asyncio.wait_for(
                self.driver.back(), timeout=self.limits.action_timeout
            )
            after_state = (
                await asyncio.wait_for(
                    self.driver.wait_for_idle(self.limits.action_timeout),
                    timeout=self.limits.action_timeout + 0.5,
                )
                if operation.status == CapabilityStatus.AVAILABLE
                else None
            )
        except asyncio.TimeoutError:
            operation = DeviceOperation(
                CapabilityStatus.FAILED,
                "UI back action timeout을 초과했습니다.",
                synthetic=self.synthetic,
            )
            after_state = None
        evidence_ids = list(before_evidence)
        if self.hooks.after_action:
            evidence_ids.extend(
                await self.hooks.after_action(
                    sequence, state, candidate, operation, after_state, before_evidence
                )
            )
        action = NavigationAction(
            sequence=sequence,
            action_type="back",
            element_id=None,
            label=candidate.label,
            risk="low",
            source_state=state.fingerprint,
            destination_state=after_state.fingerprint if after_state else None,
            result=operation.status.value,
            message=operation.message,
            timestamp=self._now(),
            evidence_ids=list(dict.fromkeys(evidence_ids)),
            command=operation.command,
            synthetic=bool(operation.synthetic or self.synthetic),
        )
        self._actions.append(action)
        await self._update("action", action=action.to_dict())
        return after_state

    async def _execute_scroll(
        self, state: UIState, container_id: str
    ) -> tuple[NavigationAction, UIState | None]:
        candidate = NavigationCandidate(
            action_type="swipe",
            element_id=container_id,
            label="스크롤 가능한 영역",
            risk="low",
            rationale="대상 앱의 scrollable container 내부에서만 제한적으로 위로 스와이프합니다.",
        )
        sequence = len(self._actions) + 1
        before_evidence: list[str] = []
        if self.hooks.before_action:
            before_evidence = await self.hooks.before_action(sequence, state, candidate)
        operation: DeviceOperation
        after_state: UIState | None = None
        try:
            live_state = await asyncio.wait_for(
                self.driver.dump_ui(), timeout=self.limits.action_timeout
            )
            container = live_state.element(container_id)
            if live_state.fingerprint != state.fingerprint or not container:
                operation = DeviceOperation(
                    CapabilityStatus.FAILED,
                    "실행 직전 UI Tree가 변경되어 stale scroll을 차단했습니다.",
                    synthetic=self.synthetic,
                )
            elif (
                not container.scrollable
                or not container.enabled
                or container.bounds.area <= 0
                or (
                    container.package
                    and self.target_package
                    and container.package != self.target_package
                )
            ):
                operation = DeviceOperation(
                    CapabilityStatus.MANUAL_REQUIRED,
                    "검증된 대상 앱 scrollable container가 아니어서 스와이프를 차단했습니다.",
                    synthetic=self.synthetic,
                )
            else:
                bounds = container.bounds
                x = (bounds.left + bounds.right) // 2
                start_y = bounds.top + int((bounds.bottom - bounds.top) * 0.8)
                end_y = bounds.top + int((bounds.bottom - bounds.top) * 0.25)
                operation = await asyncio.wait_for(
                    self.driver.swipe(x, start_y, x, end_y),
                    timeout=self.limits.action_timeout,
                )
                if operation.status == CapabilityStatus.AVAILABLE:
                    after_state = await asyncio.wait_for(
                        self.driver.wait_for_idle(self.limits.action_timeout),
                        timeout=self.limits.action_timeout + 0.5,
                    )
        except asyncio.TimeoutError:
            operation = DeviceOperation(
                CapabilityStatus.FAILED,
                "UI scroll timeout을 초과했습니다.",
                synthetic=self.synthetic,
            )
        evidence_ids = list(before_evidence)
        if self.hooks.after_action:
            evidence_ids.extend(
                await self.hooks.after_action(
                    sequence,
                    state,
                    candidate,
                    operation,
                    after_state,
                    list(before_evidence),
                )
            )
        action = NavigationAction(
            sequence=sequence,
            action_type="swipe",
            element_id=container_id,
            label=candidate.label,
            risk="low",
            source_state=state.fingerprint,
            destination_state=after_state.fingerprint if after_state else None,
            result=operation.status.value,
            message=operation.message,
            timestamp=self._now(),
            evidence_ids=list(dict.fromkeys(evidence_ids)),
            command=operation.command,
            synthetic=bool(operation.synthetic or self.synthetic),
        )
        self._actions.append(action)
        await self._update("action", action=action.to_dict())
        return action, after_state

    @staticmethod
    def _scroll_container(state: UIState):
        candidates = [
            item
            for item in state.elements
            if item.scrollable and item.enabled and item.bounds.area > 0
        ]
        return max(candidates, key=lambda item: item.bounds.area, default=None)

    async def _explore(self, state: UIState, depth: int) -> UIState:
        # Preserve the observed destination even when the action that reached it
        # consumes the final action/time budget.
        if not self._add_state(state):
            return state
        if self._limit_reached():
            return state
        await self._update("state", state=state.to_dict(include_elements=False), depth=depth)
        candidates = self.policy.candidates(state, self.target_package)
        for candidate in candidates:
            if candidate.requires_approval or candidate.risk != "low":
                await self._queue_risky(state, candidate)
        safe = [
            item
            for item in candidates
            if item.risk == "low" and not item.requires_approval
        ][: self.limits.per_screen_action_limit]
        if depth >= self.limits.max_depth:
            safe = []

        current = state
        for candidate in safe:
            if self._limit_reached():
                break
            attempt_key = (state.fingerprint, candidate.element_id)
            if attempt_key in self._attempted:
                continue
            self._attempted.add(attempt_key)
            live = await self.driver.dump_ui()
            if live.fingerprint != state.fingerprint:
                current = live
                break
            action, after = await self._execute(state, candidate)
            if action.result != CapabilityStatus.AVAILABLE.value or not after:
                continue
            if after.package and after.package != self.target_package:
                self._termination_reason = "left_target_package"
                current = after
                break
            if after.fingerprint == state.fingerprint:
                self._visits[after.fingerprint] += 1
                if self._visits[after.fingerprint] >= self.limits.repeated_state_limit:
                    continue
            elif self._visits[after.fingerprint] < self.limits.repeated_state_limit:
                current = await self._explore(after, depth + 1)
            if self._limit_reached():
                break
            restored = await self._execute_back(current)
            if not restored:
                break
            current = restored
            self._visits[current.fingerprint] += 1
            if current.fingerprint != state.fingerprint:
                self._termination_reason = "back_navigation_mismatch"
                break
        if (
            current.fingerprint == state.fingerprint
            and not self._limit_reached()
            and self.limits.max_scrolls_per_state > 0
        ):
            container = self._scroll_container(state)
            structure = state.structural_fingerprint
            if (
                container
                and (not container.package or container.package == self.target_package)
                and self._scroll_counts[structure] < self.limits.max_scrolls_per_state
            ):
                before_view = (structure, state.content_fingerprint)
                self._seen_scroll_views.add(before_view)
                self._scroll_counts[structure] += 1
                action, after = await self._execute_scroll(state, container.element_id)
                if action.result == CapabilityStatus.AVAILABLE.value and after:
                    if after.package and after.package != self.target_package:
                        self._termination_reason = "left_target_package"
                        return after
                    after_view = (
                        after.structural_fingerprint,
                        after.content_fingerprint,
                    )
                    if after_view not in self._seen_scroll_views:
                        self._seen_scroll_views.add(after_view)
                        return await self._explore(after, depth)
        return current

    async def run(self) -> NavigationResult:
        started_at = self._now()
        self._deadline = asyncio.get_running_loop().time() + (
            self.limits.total_navigation_minutes * 60
        )
        try:
            initial = await asyncio.wait_for(
                self.driver.wait_for_idle(self.limits.action_timeout),
                timeout=self.limits.action_timeout + 0.5,
            )
            if initial.package and initial.package != self.target_package:
                raise RuntimeError(
                    f"현재 UI package({initial.package})가 대상({self.target_package})과 다릅니다."
                )
            await self._explore(initial, 0)
            status = CapabilityStatus.AVAILABLE.value
            message = (
                f"{len(self._states)}개 상태와 {len(self._actions)}개 동작을 "
                "안전 정책 안에서 탐색했습니다."
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            status = CapabilityStatus.FAILED.value
            message = str(exc)
            if not self._termination_reason or self._termination_reason == "exhausted":
                self._termination_reason = "failed"
        finished_at = self._now()
        await self._update(
            "complete", status=status, termination_reason=self._termination_reason
        )
        return NavigationResult(
            status=status,
            message=message,
            termination_reason=self._termination_reason,
            states=list(self._states.values()),
            actions=self._actions,
            pending_approval=list(self._pending.values()),
            limits=self.limits,
            started_at=started_at,
            finished_at=finished_at,
            synthetic=self.synthetic,
        )
