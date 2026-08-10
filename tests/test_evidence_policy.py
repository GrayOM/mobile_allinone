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


def test_local_storage_confirmation_requires_actual_storage_evidence():
    policy = EvidencePolicyEngine()
    evidence = {
        "network": _evidence("network", "network_capture"),
        "log": _evidence("log", "device_log"),
        "screen": _evidence("screen", "screenshot"),
    }
    incomplete = policy.decide_finding(
        category="local_storage",
        requested_verdict="confirmed",
        confidence=0.95,
        proposed_ids=["network", "log", "screen"],
        evidence_by_id=evidence,
        minimum_quality=0.55,
    )
    assert incomplete.effective_verdict == "candidate"
    assert incomplete.selected_ids == []
    assert incomplete.missing_requirements

    evidence["storage"] = _evidence("storage", "storage_snapshot")
    complete = policy.decide_finding(
        category="local_storage",
        requested_verdict="confirmed",
        confidence=0.95,
        proposed_ids=["network", "log", "storage"],
        evidence_by_id=evidence,
        minimum_quality=0.55,
    )
    assert complete.effective_verdict == "confirmed"
    assert complete.selected_ids == ["storage"]
    assert complete.missing_requirements == []


def test_sensitive_exposure_requires_source_specific_category_for_confirmation():
    policy = EvidencePolicyEngine()
    evidence = {
        "network": _evidence("network", "network_capture"),
        "log": _evidence("log", "device_log"),
    }
    ambiguous = policy.decide_finding(
        category="sensitive_data_exposure",
        requested_verdict="confirmed",
        confidence=0.95,
        proposed_ids=evidence,
        evidence_by_id=evidence,
        minimum_quality=0.55,
    )
    assert ambiguous.effective_verdict == "needs_review"
    assert "출처가 모호" in ambiguous.explanation

    network = policy.decide_finding(
        category="network_sensitive_exposure",
        requested_verdict="confirmed",
        confidence=0.95,
        proposed_ids=["network"],
        evidence_by_id=evidence,
        minimum_quality=0.55,
    )
    runtime = policy.decide_finding(
        category="runtime_log_exposure",
        requested_verdict="confirmed",
        confidence=0.95,
        proposed_ids=["log"],
        evidence_by_id=evidence,
        minimum_quality=0.55,
    )
    assert network.effective_verdict == "confirmed"
    assert runtime.effective_verdict == "confirmed"


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


def test_category_aliases_are_exact_and_do_not_match_storage_substrings():
    policy = EvidencePolicyEngine()
    assert policy.requirements_for("insecure-data-storage") == (
        ("storage_snapshot", "storage_diff"),
    )
    requirements = policy.requirements_for("network_storage_exposure")
    assert requirements != (("storage_snapshot", "storage_diff"),)
    assert "network_capture" in requirements[0]


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
