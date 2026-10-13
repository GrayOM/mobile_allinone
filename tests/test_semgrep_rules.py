from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from backend.app.analyzers.adapters import _metadata_confidence

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules" / "semgrep" / "android-security.yml"
SAMPLE = Path(__file__).parent / "fixtures" / "semgrep"


def _rules() -> list[dict]:
    return yaml.safe_load(RULES.read_text(encoding="utf-8"))["rules"]


def test_rule_metadata_uses_semgrep_compatible_types():
    rules = _rules()
    assert len(rules) >= 16
    ids = [rule["id"] for rule in rules]
    assert len(ids) == len(set(ids))
    for rule in rules:
        assert rule["id"].startswith("msw.android.")
        metadata = rule["metadata"]
        # Current Semgrep rejects float metadata values, so scores stay strings.
        assert isinstance(metadata["confidence_score"], str), rule["id"]
        assert 0 < float(metadata["confidence_score"]) <= 1
        assert metadata["masvs"].startswith("MASVS-")
        assert metadata["mastg"].startswith("MASTG-TEST-")
        assert metadata["cwe"].startswith("CWE-")
        assert metadata["category"]


def test_metadata_confidence_accepts_strings_and_bounds_values():
    assert _metadata_confidence("0.82") == pytest.approx(0.82)
    assert _metadata_confidence(0.5) == pytest.approx(0.5)
    assert _metadata_confidence("bad") == pytest.approx(0.72)
    assert _metadata_confidence("7") == 1.0


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep is optional")
def test_rules_match_the_reference_sample(tmp_path):
    # Semgrep's default ignore list skips tests/ paths, so scan a copy.
    target = tmp_path / "jadx" / "sources"
    shutil.copytree(SAMPLE, target)
    output = subprocess.run(
        ["semgrep", "scan", "--json", "--metrics=off", "--quiet", "-c", str(RULES), str(target)],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    payload = json.loads(output.stdout)
    assert payload["errors"] == []
    found = {item["check_id"].rsplit(".", 1)[-1] for item in payload["results"]}
    assert {
        "ssl-error-proceed",
        "hardcoded-key",
        "static-iv",
        "weak-digest",
        "external-storage",
        "sqlite-raw-query-concat",
        "sensitive-copy",
        "mutable-pending-intent",
        "debugging-enabled",
    } <= found


@pytest.mark.asyncio
async def test_adapter_scans_gitignored_analysis_output(tmp_path, monkeypatch):
    from backend.app.analyzers import adapters
    from backend.app.core.command import CommandResult
    from backend.app.core.config import AppSettings
    from backend.app.core.status import CapabilityStatus

    captured: dict = {}

    async def fake_run_command(args, **kwargs):
        captured["args"] = list(args)
        return CommandResult(
            status=CapabilityStatus.AVAILABLE,
            command=list(args),
            return_code=0,
            stdout=json.dumps({"results": [], "errors": [], "version": "test"}),
        )

    fake_semgrep = tmp_path / "semgrep"
    fake_semgrep.write_text("#!/bin/sh\n", encoding="utf-8")
    fake_semgrep.chmod(0o755)
    settings = AppSettings(data_dir=tmp_path / "data", database_url=f"sqlite:///{tmp_path / 'x.db'}")
    settings.tools.semgrep = str(fake_semgrep)
    monkeypatch.setattr(adapters, "run_command", fake_run_command)
    decompiled = tmp_path / "jadx"
    decompiled.mkdir()
    await adapters.SemgrepAnalyzerAdapter(settings).analyze(
        tmp_path / "app.apk", tmp_path / "out", platform="android", decompiled_dir=decompiled
    )
    assert "--no-git-ignore" in captured["args"]
    assert "--metrics=off" in captured["args"]
