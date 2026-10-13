from __future__ import annotations

import plistlib
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.app.core.config import AppSettings
from backend.app.core.status import CapabilityStatus
from backend.app.ios_signing import ZsignAdapter, load_signing_material
from backend.app.orchestration.diagnostic import (
    DiagnosticManualRequired,
    resolved_resigned_ipa,
)


def _ipa(path: Path) -> Path:
    plist = plistlib.dumps(
        {"CFBundleIdentifier": "com.example.msw.ios", "CFBundleDisplayName": "MSW iOS"}
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("Payload/Demo.app/Info.plist", plist)
        archive.writestr("Payload/Demo.app/Demo", b"\xcf\xfa\xed\xfe")
    return path


def _fake_zsign(tmp_path: Path) -> Path:
    script = tmp_path / "zsign"
    script.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "-v" ]; then echo "zsign version: 0.7"; exit 0; fi\n'
        'echo "$@" > "$(dirname "$0")/zsign-args.txt"\n'
        'out=""; last=""; key=""\n'
        'while [ $# -gt 0 ]; do\n'
        '  if [ "$1" = "-o" ]; then out="$2"; shift; fi\n'
        '  if [ "$1" = "-k" ]; then key="$2"; shift; fi\n'
        '  last="$1"; shift\n'
        "done\n"
        'grep -q "PRIVATE KEY" "$key" || exit 3\n'
        'cp "$last" "$out"\n',
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def _make_p12(password: str) -> bytes:
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MSW Test Signing")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return pkcs12.serialize_key_and_certificates(
        b"msw", key, certificate, None,
        serialization.BestAvailableEncryption(password.encode()),
    )


def _signing_env(monkeypatch, tmp_path: Path) -> None:
    provision = tmp_path / "dev.mobileprovision"
    provision.write_bytes(b"profile")
    p12 = tmp_path / "dev.p12"
    p12.write_bytes(_make_p12("s3cret-pass"))
    monkeypatch.setenv("MSW_IOS_SIGNING_PROVISION", str(provision))
    monkeypatch.setenv("MSW_IOS_SIGNING_P12", str(p12))
    monkeypatch.setenv("MSW_IOS_SIGNING_P12_PASSWORD", "s3cret-pass")


def test_signing_material_requires_profile_and_credentials(monkeypatch):
    for name in (
        "MSW_IOS_SIGNING_PROVISION",
        "MSW_IOS_SIGNING_P12",
        "MSW_IOS_SIGNING_P12_PASSWORD",
        "MSW_IOS_SIGNING_KEY",
        "MSW_IOS_SIGNING_CERT",
    ):
        monkeypatch.delenv(name, raising=False)
    material = load_signing_material()
    assert not material.ready
    assert len(material.problems) == 2


@pytest.mark.skipif(sys.platform == "win32", reason="fake zsign is a POSIX shell script")
@pytest.mark.asyncio
async def test_zsign_resign_masks_password_and_hashes_output(monkeypatch, tmp_path):
    _signing_env(monkeypatch, tmp_path)
    settings = AppSettings(data_dir=tmp_path / "data", database_url=f"sqlite:///{tmp_path / 'x.db'}")
    settings.tools.zsign = str(_fake_zsign(tmp_path))
    adapter = ZsignAdapter(settings)
    health = await adapter.health()
    assert health["status"] == "available"
    assert health["version"] == "0.7"
    assert "s3cret-pass" not in str(health)

    source = _ipa(tmp_path / "upload.ipa")
    outcome = await adapter.resign(source, output_dir=tmp_path / "resigned")
    assert outcome.status == CapabilityStatus.AVAILABLE
    assert outcome.output_path and outcome.output_path.is_file()
    assert outcome.sha256 and len(outcome.sha256) == 64
    assert "s3cret-pass" not in " ".join(outcome.command)
    invoked = (tmp_path / "zsign-args.txt").read_text(encoding="utf-8")
    assert "s3cret-pass" not in invoked
    assert "-p" not in invoked.split()
    assert "signing-key.pem" in invoked
    assert not any(Path(item).exists() for item in invoked.split() if item.endswith(".pem"))
    assert source.read_bytes() == _ipa(tmp_path / "again.ipa").read_bytes()


@pytest.mark.asyncio
async def test_zsign_rejects_non_ipa_and_missing_tool(monkeypatch, tmp_path):
    _signing_env(monkeypatch, tmp_path)
    settings = AppSettings(data_dir=tmp_path / "data", database_url=f"sqlite:///{tmp_path / 'x.db'}")
    settings.tools.zsign = str(tmp_path / "missing-zsign")
    not_ipa = tmp_path / "file.ipa"
    not_ipa.write_bytes(b"not a zip")
    assert (await ZsignAdapter(settings).resign(not_ipa, output_dir=tmp_path)).status == CapabilityStatus.FAILED
    missing = await ZsignAdapter(settings).resign(_ipa(tmp_path / "ok.ipa"), output_dir=tmp_path / "out")
    assert missing.status == CapabilityStatus.NOT_CONFIGURED


def test_resigned_ipa_resolution_verifies_source_and_hash(tmp_path):
    stored = _ipa(tmp_path / "upload.ipa")
    resigned_dir = tmp_path / "resigned"
    resigned_dir.mkdir()
    signed = resigned_dir / "upload-resigned.ipa"
    signed.write_bytes(stored.read_bytes())
    import hashlib

    digest = hashlib.sha256(signed.read_bytes()).hexdigest()
    app = SimpleNamespace(
        platform="ios",
        sha256="source-sha",
        stored_path=str(stored),
        analysis_result={
            "ios_resigned": {"file_name": signed.name, "sha256": digest, "source_sha256": "source-sha"}
        },
    )
    assert resolved_resigned_ipa(app) == signed
    signed.write_bytes(b"tampered")
    with pytest.raises(DiagnosticManualRequired):
        resolved_resigned_ipa(app)
    app.analysis_result["ios_resigned"]["source_sha256"] = "other"
    with pytest.raises(DiagnosticManualRequired):
        resolved_resigned_ipa(app)
    android = SimpleNamespace(platform="android", analysis_result={}, sha256="", stored_path=str(stored))
    with pytest.raises(DiagnosticManualRequired):
        resolved_resigned_ipa(android)


def test_mock_ipa_resign_endpoint_records_synthetic_copy(client, tmp_path):
    project = client.post(
        "/api/projects",
        json={"name": "iOS 재서명 Mock", "run_mode": "mock", "ai_enabled": False},
    ).json()
    ipa = _ipa(tmp_path / "mock.ipa")
    with ipa.open("rb") as stream:
        upload = client.post(
            f"/api/projects/{project['id']}/apps/upload",
            files={"file": (ipa.name, stream, "application/octet-stream")},
        )
    assert upload.status_code == 201
    app = upload.json()
    assert app["platform"] in {"ios", "mock_ios"}
    wrong = client.post(
        f"/api/apps/{app['id']}/ios/resign",
        json={"requested_by": "tester", "confirm_original_sha256": "0" * 64},
    )
    assert wrong.status_code == 409
    response = client.post(
        f"/api/apps/{app['id']}/ios/resign",
        json={"requested_by": "tester", "confirm_original_sha256": app["sha256"]},
    )
    assert response.status_code == 200
    record = response.json()
    assert record["synthetic"] is True
    assert record["source_sha256"] == app["sha256"]
    assert "path" not in record
    status = client.get("/api/ios/signing")
    assert status.status_code == 200
