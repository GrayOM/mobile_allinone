from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Awaitable, Callable

from backend.app.core.status import CapabilityStatus
from backend.app.devices.base import DeviceOperation

from .base import UIDriver
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
        if len(self._states) >= self.limits.max_states:
            self._termination_reason = "max_states"
            return False
        self._states[state.fingerprint] = state
        return True

    def _queue_risky(self, state: UIState, candidate: NavigationCandidate) -> None:
        key = (state.fingerprint, candidate.element_id)
        self._pending.setdefault(
            key,
            {
                **candidate.to_dict(),
                "state_fingerprint": state.fingerprint,
                "package": state.package,
                "activity": state.activity,
                "status": "pending_approval",
                "queued_at": self._now(),
            },
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
                self._queue_risky(live_state, rechecked)
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
                self._queue_risky(state, candidate)
        safe = [
            item
            for item in candidates
            if item.risk == "low" and not item.requires_approval
        ][: self.limits.per_screen_action_limit]
        if depth >= self.limits.max_depth:
            return state

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
