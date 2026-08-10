from __future__ import annotations

from backend.app.database.models import Evidence
from backend.app.evidence import EvidencePolicyEngine
from backend.app.navigation import UIState


def _evidence(identifier: str, evidence_type: str) -> Evidence:
    return Evidence(
        id=identifier,
        run_id="run",
        evidence_type=evidence_type,
        title=evidence_type,
        sequence=1,
        synthetic=True,
    )


def test_confirmed_finding_requires_category_specific_evidence_groups():
    policy = EvidencePolicyEngine()
    evidence = {
        "network": _evidence("network", "network_capture"),
        "log": _evidence("log", "device_log"),
        "screen": _evidence("screen", "screenshot"),
    }
    incomplete = policy.decide_finding(
        category="sensitive_data_exposure",
        requested_verdict="confirmed",
        confidence=0.95,
        proposed_ids=["network", "screen"],
        evidence_by_id=evidence,
        minimum_quality=0.55,
    )
    assert incomplete.effective_verdict == "needs_review"
    assert incomplete.selected_ids == ["network"]
    assert incomplete.missing_requirements

    complete = policy.decide_finding(
        category="sensitive_data_exposure",
        requested_verdict="confirmed",
        confidence=0.95,
        proposed_ids=["network", "log", "screen"],
        evidence_by_id=evidence,
        minimum_quality=0.55,
    )
    assert complete.effective_verdict == "confirmed"
    assert complete.selected_ids == ["network", "log"]
    assert complete.missing_requirements == []


def test_finding_without_relevant_evidence_remains_candidate():
    decision = EvidencePolicyEngine().decide_finding(
        category="authorization_boundary",
        requested_verdict="likely",
        confidence=0.9,
        proposed_ids=[],
        evidence_by_id={},
        minimum_quality=0.55,
    )
    assert decision.effective_verdict == "candidate"


def test_evidence_policy_detects_activity_text_dialog_and_runtime_events():
    before = UIState.from_xml(
        '<?xml version="1.0"?><hierarchy><node text="Home" content-desc="" '
        'resource-id="demo:id/home" class="android.widget.TextView" package="demo" '
        'bounds="[0,0][100,100]" clickable="false" enabled="true" scrollable="false" '
        'password="false" selected="false" checked="false" /></hierarchy>',
        package="demo",
        activity=".Home",
    )
    after = UIState.from_xml(
        '<?xml version="1.0"?><hierarchy><node text="Warning" content-desc="" '
        'resource-id="demo:id/dialog" class="android.app.Dialog" package="demo" '
        'bounds="[0,0][100,100]" clickable="false" enabled="true" scrollable="false" '
        'password="false" selected="false" checked="false" /></hierarchy>',
        package="demo",
        activity=".Details",
    )
    triggers = EvidencePolicyEngine.transition_triggers(
        before, after, event_signals=["network_request", "unknown"]
    )
    assert triggers == [
        "activity_changed",
        "important_text_changed",
        "dialog_appeared",
        "network_request",
    ]
