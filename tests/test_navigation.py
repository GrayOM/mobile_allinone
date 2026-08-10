from __future__ import annotations

import asyncio
import time

import pytest

from backend.app.core.status import CapabilityStatus
from backend.app.devices.base import DeviceOperation
from backend.app.navigation import (
    MockAndroidUIDriver,
    NavigationEngine,
    NavigationLimits,
    UIState,
)


def _xml(nodes: list[str]) -> str:
    return '<?xml version="1.0"?><hierarchy>' + "".join(nodes) + "</hierarchy>"


def _node(text: str, resource: str, bounds: str = "[0,0][100,100]") -> str:
    return (
        f'<node text="{text}" content-desc="" resource-id="demo:id/{resource}" '
        f'class="android.widget.Button" package="demo" bounds="{bounds}" '
        'clickable="true" enabled="true" scrollable="false" password="false" '
        'selected="false" checked="false" />'
    )


def test_navigation_state_fingerprint_is_normalized_and_content_sensitive():
    first = UIState.from_xml(
        _xml([_node("Account", "account"), _node("Help", "help", "[0,100][100,200]")]),
        package="demo",
        activity=".Main",
    )
    reordered = UIState.from_xml(
        _xml([_node("Help", "help", "[0,100][100,200]"), _node("Account", "account")]),
        package="demo",
        activity=".Main",
    )
    changed = UIState.from_xml(
        _xml([_node("Account changed", "account"), _node("Help", "help", "[0,100][100,200]")]),
        package="demo",
        activity=".Main",
    )
    assert first.fingerprint == reordered.fingerprint
    assert first.fingerprint != changed.fingerprint


@pytest.mark.asyncio
async def test_dangerous_ui_actions_enter_approval_queue_and_are_never_executed():
    result = await NavigationEngine(
        MockAndroidUIDriver(package_name="com.example.demo"),
        target_package="com.example.demo",
        limits=NavigationLimits(max_states=20, max_depth=4, max_actions=30),
        synthetic=True,
    ).run()

    pending_labels = {str(item["label"]) for item in result.pending_approval}
    executed_labels = {item.label for item in result.actions}
    assert {"송금", "로그아웃"}.issubset(pending_labels)
    assert not ({"송금", "로그아웃"} & executed_labels)
    assert all(item.synthetic for item in result.actions)


class RepeatingDriver(MockAndroidUIDriver):
    async def tap(self, x: int, y: int) -> DeviceOperation:
        return DeviceOperation(
            CapabilityStatus.AVAILABLE,
            "화면이 바뀌지 않는 합성 동작",
            command="mock repeat",
            synthetic=True,
        )


@pytest.mark.asyncio
async def test_repeated_state_loop_is_bounded():
    result = await NavigationEngine(
        RepeatingDriver(package_name="com.example.demo"),
        target_package="com.example.demo",
        limits=NavigationLimits(
            max_states=10,
            max_depth=5,
            max_actions=20,
            per_screen_action_limit=5,
            repeated_state_limit=2,
            total_navigation_minutes=0.2,
        ),
        synthetic=True,
    ).run()
    assert len(result.states) == 1
    assert len(result.actions) == 2
    assert result.termination_reason == "exhausted"


class SlowInitialDriver(MockAndroidUIDriver):
    async def wait_for_idle(self, timeout_seconds: float = 5.0) -> UIState:
        await asyncio.sleep(0.08)
        return await self.dump_ui()


@pytest.mark.asyncio
async def test_navigation_total_timeout_stops_before_unbounded_actions():
    result = await NavigationEngine(
        SlowInitialDriver(package_name="com.example.demo"),
        target_package="com.example.demo",
        limits=NavigationLimits(
            max_states=20,
            max_depth=5,
            max_actions=50,
            action_timeout=1,
            total_navigation_minutes=0.001,
        ),
        synthetic=True,
    ).run()
    assert result.status == CapabilityStatus.AVAILABLE.value
    assert result.termination_reason == "timeout"
    assert not result.actions


def _wait_for_terminal(client, run_id: str) -> dict:
    deadline = time.time() + 30
    while time.time() < deadline:
        run = client.get(f"/api/runs/{run_id}").json()
        if run["status"] in {
            "completed",
            "completed_with_gaps",
            "manual_required",
            "failed",
        }:
            return run
        time.sleep(0.05)
    raise AssertionError("run did not finish")


def test_mock_navigation_persists_ordered_before_after_evidence(client):
    demo = client.post("/api/demo/bootstrap").json()
    started = client.post(
        "/api/runs",
        json={
            "project_id": demo["project"]["id"],
            "app_id": demo["app"]["id"],
            "device_id": "mock-android-01",
            "device_adapter": "mock",
            "proxy_adapter": "mock",
            "options": {
                "auto_navigation": True,
                "navigation_limits": {
                    "max_states": 2,
                    "max_depth": 1,
                    "max_actions": 1,
                    "per_screen_action_limit": 1,
                    "action_timeout": 2,
                    "total_navigation_minutes": 0.2,
                },
            },
        },
    )
    assert started.status_code == 201
    run = _wait_for_terminal(client, started.json()["id"])
    assert run["status"] == "completed"
    navigation = run["options"]["navigation"]
    assert navigation["state_count"] == 2
    assert navigation["action_count"] == 1
    assert navigation["synthetic"] is True
    assert any(item["label"] == "송금" for item in navigation["pending_approval"])

    evidence = client.get(f"/api/runs/{run['id']}/evidence").json()
    transition = [
        item
        for item in evidence
        if item["title"].startswith("UI 동작 001")
    ]
    assert [item["evidence_type"] for item in transition] == [
        "screenshot",
        "ui_tree",
        "navigation_action",
        "screenshot",
        "ui_tree",
    ]
    graph = next(item for item in evidence if item["evidence_type"] == "navigation_graph")
    action = navigation["actions"][0]
    assert action["evidence_ids"] == [item["id"] for item in transition]
    assert navigation["graph_evidence_id"] == graph["id"]
