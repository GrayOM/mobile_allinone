"""Cross-platform IPA re-signing with zsign (no macOS required).

The workbench signs an uploaded IPA with the operator's own Apple
development certificate and provisioning profile so it can be installed on an
authorized test device from Windows or Linux. Signing material is read from
``.env`` only:

* ``MSW_IOS_SIGNING_PROVISION`` – ``.mobileprovision`` path (required)
* either ``MSW_IOS_SIGNING_P12`` + ``MSW_IOS_SIGNING_P12_PASSWORD``
* or ``MSW_IOS_SIGNING_KEY`` (PEM private key) + ``MSW_IOS_SIGNING_CERT`` (PEM)

The original upload is never modified. The signed copy is written next to it,
hashed, and recorded on the app with signer metadata. A P12 is decrypted in
memory and passed to zsign as a short-lived PEM pair in a private temporary
directory, so the password never appears in a process command line.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import tempfile
import re
import shutil
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.app.core.command import run_command
from backend.app.core.config import AppSettings
from backend.app.core.status import CapabilityStatus

MASK = "********"


@dataclass(slots=True)
class SigningMaterial:
    provision: Path | None
    p12: Path | None
    p12_password: str | None
    key: Path | None
    cert: Path | None
    problems: list[str] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return not self.problems

    def describe(self) -> dict[str, Any]:
        return {
            "provision_configured": self.provision is not None,
            "credential_type": "p12" if self.p12 else ("pem" if self.key else None),
            "problems": list(self.problems),
        }


@dataclass(slots=True)
class ResignOutcome:
    status: CapabilityStatus
    message: str
    output_path: Path | None = None
    sha256: str | None = None
    size_bytes: int = 0
    command: list[str] = field(default_factory=list)
    zsign_version: str | None = None
    synthetic: bool = False


def _env_path(name: str) -> Path | None:
    value = (os.getenv(name) or "").strip()
    return Path(value).expanduser() if value else None


def load_signing_material() -> SigningMaterial:
    material = SigningMaterial(
        provision=_env_path("MSW_IOS_SIGNING_PROVISION"),
        p12=_env_path("MSW_IOS_SIGNING_P12"),
        p12_password=os.getenv("MSW_IOS_SIGNING_P12_PASSWORD"),
        key=_env_path("MSW_IOS_SIGNING_KEY"),
        cert=_env_path("MSW_IOS_SIGNING_CERT"),
    )
    if material.provision is None:
        material.problems.append("MSW_IOS_SIGNING_PROVISION이 설정되지 않았습니다.")
    elif not material.provision.is_file():
        material.problems.append("프로비저닝 프로파일 파일을 찾을 수 없습니다.")
    if material.p12 is not None:
        if not material.p12.is_file():
            material.problems.append("P12 인증서 파일을 찾을 수 없습니다.")
        if material.p12_password is None:
            material.problems.append("MSW_IOS_SIGNING_P12_PASSWORD가 필요합니다.")
    elif material.key is not None:
        if not material.key.is_file():
            material.problems.append("PEM 개인키 파일을 찾을 수 없습니다.")
        if material.cert is None or not material.cert.is_file():
            material.problems.append("MSW_IOS_SIGNING_CERT PEM 인증서가 필요합니다.")
    else:
        material.problems.append(
            "MSW_IOS_SIGNING_P12 또는 MSW_IOS_SIGNING_KEY/MSW_IOS_SIGNING_CERT가 필요합니다."
        )
    return material


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_ipa(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as archive:
            return any(
                name.startswith("Payload/") and name.endswith(".app/Info.plist")
                for name in archive.namelist()
            )
    except (OSError, zipfile.BadZipFile):
        return False


class ZsignAdapter:
    name = "zsign"

    def __init__(self, settings: AppSettings):
        self.settings = settings

    async def health(self) -> dict[str, Any]:
        binary = self.settings.resolved_tool("zsign")
        material = load_signing_material()
        version = None
        if binary:
            result = await run_command([binary, "-v"], timeout=15)
            match = re.search(r"(\d+\.\d+(?:\.\d+)?)", result.stdout + result.stderr)
            version = match.group(1) if match else None
        if not binary:
            status = CapabilityStatus.NOT_CONFIGURED
            message = "zsign 실행 파일 경로가 필요합니다 (설정 > 도구 경로 zsign)."
        elif not material.ready:
            status = CapabilityStatus.NOT_CONFIGURED
            message = "서명 인증서·프로비저닝 프로파일 환경변수를 확인하세요."
        else:
            status = CapabilityStatus.AVAILABLE
            message = "macOS 없이 IPA 재서명을 실행할 수 있습니다."
        return {
            "name": self.name,
            "status": status.value,
            "message": message,
            "path": binary,
            "version": version,
            "signing": material.describe(),
            "integration": "subprocess",
        }

    async def resign(
        self,
        source: Path,
        *,
        output_dir: Path,
        synthetic: bool = False,
    ) -> ResignOutcome:
        if not await asyncio.to_thread(lambda: source.is_file() and _is_ipa(source)):
            return ResignOutcome(CapabilityStatus.FAILED, "유효한 IPA 원본을 찾을 수 없습니다.")
        output_dir.mkdir(parents=True, exist_ok=True)
        output = output_dir / f"{source.stem}-resigned-{uuid.uuid4()}.ipa"
        if synthetic:
            await asyncio.to_thread(shutil.copyfile, source, output)
            return ResignOutcome(
                CapabilityStatus.AVAILABLE,
                "SYNTHETIC MOCK 재서명입니다. 실제 서명은 적용되지 않았습니다.",
                output_path=output,
                sha256=await asyncio.to_thread(_sha256, output),
                size_bytes=output.stat().st_size,
                command=["mock-zsign", source.name],
                zsign_version="synthetic",
                synthetic=True,
            )
        binary = self.settings.resolved_tool("zsign")
        if not binary:
            return ResignOutcome(
                CapabilityStatus.NOT_CONFIGURED,
                "zsign 실행 파일이 없어 IPA 재서명은 수동 작업이 필요합니다.",
            )
        material = load_signing_material()
        if not material.ready:
            return ResignOutcome(
                CapabilityStatus.NOT_CONFIGURED,
                " ".join(material.problems),
            )
        with tempfile.TemporaryDirectory(prefix="msw-zsign-") as private_dir:
            # zsign only accepts a P12 password on its command line, where any
            # local process could read it. Decrypt the P12 in memory instead and
            # hand zsign a short-lived PEM pair in a private directory.
            if material.p12 is not None:
                try:
                    key_path, cert_path = await asyncio.to_thread(
                        _p12_to_private_pem,
                        material.p12,
                        material.p12_password or "",
                        Path(private_dir),
                    )
                except ValueError as exc:
                    return ResignOutcome(CapabilityStatus.FAILED, f"P12 인증서를 열 수 없습니다: {exc}")
                credential_display = [f"{material.p12.name}→PEM(임시)"]
            else:
                key_path, cert_path = material.key, material.cert
                credential_display = [key_path.name if key_path else "", cert_path.name if cert_path else ""]
            args = [
                binary,
                "-k", str(key_path),
                "-c", str(cert_path),
                "-m", str(material.provision),
                "-o", str(output),
                "-z", "9",
                str(source),
            ]
            display = [
                binary,
                "-k/-c", *credential_display,
                "-m", material.provision.name if material.provision else "",
                "-o", output.name,
                "-z", "9",
                source.name,
            ]
            result = await run_command(
                args,
                timeout=600,
                memory_limit_mb=self.settings.external_tool_memory_mb,
                cpu_limit_seconds=self.settings.external_tool_cpu_seconds,
            )
        valid = result.ok and await asyncio.to_thread(lambda: output.is_file() and _is_ipa(output))
        if not valid:
            output.unlink(missing_ok=True)
            detail = result.error or result.stderr or result.stdout
            if material.p12_password:
                detail = detail.replace(material.p12_password, MASK)
            return ResignOutcome(
                CapabilityStatus.FAILED,
                f"zsign 재서명 실패: {detail.strip()[:400]}",
                command=display,
            )
        return ResignOutcome(
            CapabilityStatus.AVAILABLE,
            "IPA 재서명을 완료했습니다. 원본 업로드는 변경하지 않았습니다.",
            output_path=output,
            sha256=await asyncio.to_thread(_sha256, output),
            size_bytes=output.stat().st_size,
            command=display,
        )


def _p12_to_private_pem(p12: Path, password: str, directory: Path) -> tuple[Path, Path]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12

    key, certificate, _ = pkcs12.load_key_and_certificates(
        p12.read_bytes(), password.encode("utf-8") if password else None
    )
    if key is None or certificate is None:
        raise ValueError("개인키 또는 인증서가 없는 P12입니다.")
    directory.chmod(0o700)
    key_path = directory / "signing-key.pem"
    cert_path = directory / "signing-cert.pem"
    descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return key_path, cert_path


def resigned_record(outcome: ResignOutcome, *, source_sha256: str, requested_by: str) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "file_name": outcome.output_path.name if outcome.output_path else None,
        "sha256": outcome.sha256,
        "size_bytes": outcome.size_bytes,
        "source_sha256": source_sha256,
        "command": outcome.command,
        "requested_by": requested_by,
        "synthetic": outcome.synthetic,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
