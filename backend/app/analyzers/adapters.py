from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any, Iterable

import httpx

from backend.app.core.command import run_command
from backend.app.core.status import CapabilityStatus

from .base import AnalyzerAdapter, AnalyzerFinding, AnalyzerResult


def _severity(value: Any, default: str = "info") -> str:
    text = str(value or default).strip().lower()
    aliases = {
        "error": "high",
        "warning": "medium",
        "warn": "medium",
        "note": "low",
        "critical": "high",
    }
    text = aliases.get(text, text)
    return text if text in {"critical", "high", "medium", "low", "info"} else default


def _flatten_matches(value: Any, prefix: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield from _flatten_matches(child, path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _flatten_matches(child, f"{prefix}[{index}]")
    elif value not in (None, "", False):
        yield prefix, str(value)


class AndroguardAnalyzerAdapter(AnalyzerAdapter):
    name = "androguard"

    async def health(self) -> dict[str, Any]:
        try:
            import androguard

            return {
                "name": self.name,
                "status": CapabilityStatus.AVAILABLE.value,
                "version": getattr(androguard, "__version__", "unknown"),
                "integration": "python",
            }
        except ImportError:
            return {
                "name": self.name,
                "status": CapabilityStatus.NOT_CONFIGURED.value,
                "version": None,
                "integration": "python",
                "install_hint": "py -m pip install androguard",
            }

    async def analyze(
        self,
        artifact_path: Path,
        output_dir: Path,
        *,
        platform: str,
        decompiled_dir: Path | None = None,
    ) -> AnalyzerResult:
        result = AnalyzerResult(self.name, CapabilityStatus.NOT_CONFIGURED)
        if platform != "android":
            result.status = CapabilityStatus.UNSUPPORTED
            result.error = "Androguard는 Android APK 분석에만 사용합니다."
            return result.finish()
        try:
            import androguard
            from androguard.core.apk import APK
            from loguru import logger

            logger.disable("androguard")
        except ImportError:
            result.error = "Androguard가 설치되지 않았습니다."
            return result.finish()

        result.version = getattr(androguard, "__version__", "unknown")
        try:
            payload = await asyncio.to_thread(self._inspect, APK, artifact_path)
            result.status = CapabilityStatus.AVAILABLE
            result.enrichment = payload.pop("_enrichment", {})
            result.metadata = {
                "permissions": len(payload.get("permissions", [])),
                "components": sum(
                    len(payload.get(name, []))
                    for name in ("activities", "services", "receivers", "providers")
                ),
            }
            result.save_raw(output_dir, payload)
        except Exception as exc:
            result.status = CapabilityStatus.FAILED
            result.error = f"{type(exc).__name__}: {exc}"
        return result.finish()

    @staticmethod
    def _inspect(apk_class, artifact_path: Path) -> dict[str, Any]:
        apk = apk_class(str(artifact_path))
        manifest_text = ""
        try:
            manifest = apk.get_android_manifest_xml()
            try:
                from lxml import etree

                manifest_text = etree.tostring(
                    manifest, encoding="unicode", pretty_print=False
                )
            except (ImportError, TypeError):
                import xml.etree.ElementTree as ET

                manifest_text = ET.tostring(manifest, encoding="unicode")
        except Exception:
            manifest_text = ""

        def safe(name: str, default: Any):
            try:
                value = getattr(apk, name)()
                return value if value is not None else default
            except Exception:
                return default

        payload = {
            "package_name": safe("get_package", None),
            "app_name": safe("get_app_name", None),
            "version_name": safe("get_androidversion_name", None),
            "version_code": safe("get_androidversion_code", None),
            "min_sdk": safe("get_min_sdk_version", None),
            "target_sdk": safe("get_target_sdk_version", None),
            "permissions": sorted(safe("get_permissions", [])),
            "activities": sorted(safe("get_activities", [])),
            "services": sorted(safe("get_services", [])),
            "receivers": sorted(safe("get_receivers", [])),
            "providers": sorted(safe("get_providers", [])),
            "libraries": sorted(safe("get_libraries", [])),
            "files": sorted(safe("get_files", []))[:5000],
            "_enrichment": {
                "manifest_text": manifest_text,
                "package_name": safe("get_package", None),
                "app_name": safe("get_app_name", None),
                "version": safe("get_androidversion_name", None),
            },
        }
        return payload


class APKiDAnalyzerAdapter(AnalyzerAdapter):
    name = "apkid"

    async def health(self) -> dict[str, Any]:
        executable = self.settings.resolved_tool("apkid")
        if not executable:
            return {
                "name": self.name,
                "status": CapabilityStatus.NOT_CONFIGURED.value,
                "install_hint": "py -m pip install apkid (GPL/상용 이중 라이선스 확인)",
                "integration": "subprocess",
            }
        version = await run_command([executable, "--version"], timeout=15)
        return {
            "name": self.name,
            "status": CapabilityStatus.AVAILABLE.value,
            "version": (version.stdout or version.stderr).strip()[:160],
            "path": executable,
            "integration": "subprocess",
        }

    async def analyze(
        self,
        artifact_path: Path,
        output_dir: Path,
        *,
        platform: str,
        decompiled_dir: Path | None = None,
    ) -> AnalyzerResult:
        executable = self.settings.resolved_tool("apkid")
        result = AnalyzerResult(self.name, CapabilityStatus.NOT_CONFIGURED)
        if platform != "android":
            result.status = CapabilityStatus.UNSUPPORTED
            result.error = "APKiD는 Android APK/DEX에만 사용합니다."
            return result.finish()
        if not executable:
            result.error = "APKiD 실행 파일을 찾을 수 없습니다."
            return result.finish()
        command = [executable, "-j", str(artifact_path)]
        result.command = command
        executed = await run_command(
            command,
            timeout=180,
            memory_limit_mb=self.settings.external_tool_memory_mb,
            cpu_limit_seconds=self.settings.external_tool_cpu_seconds,
        )
        if not executed.ok:
            result.status = executed.status
            result.error = executed.error or executed.stderr.strip()[:1000]
            return result.finish()
        try:
            payload = json.loads(executed.stdout)
        except json.JSONDecodeError as exc:
            result.status = CapabilityStatus.FAILED
            result.error = f"APKiD JSON 해석 실패: {exc}"
            result.save_raw(output_dir, {"stdout": executed.stdout, "stderr": executed.stderr})
            return result.finish()

        result.status = CapabilityStatus.AVAILABLE
        result.save_raw(output_dir, payload)
        interesting = re.compile(
            r"(packer|protector|obfuscat|anti[_ -]?(?:vm|debug|disassembl)|rasp|compiler)",
            re.I,
        )
        for path, value in _flatten_matches(payload):
            if not interesting.search(path):
                continue
            category = "obfuscation"
            if re.search(r"packer|protector|rasp", path, re.I):
                category = "app_protection"
            result.findings.append(
                AnalyzerFinding(
                    title=f"APKiD 보호·빌드 시그니처: {value[:120]}",
                    category=category,
                    severity="info",
                    location=path or artifact_path.name,
                    rationale="APK에서 컴파일러·난독화·패커·보호 솔루션 시그니처가 식별되었습니다.",
                    confidence=0.82,
                    source_tool=self.name,
                    rule_id=path or "signature",
                    verdict="informational",
                    raw={"match": value},
                )
            )
        result.metadata["match_count"] = len(result.findings)
        return result.finish()


class SemgrepAnalyzerAdapter(AnalyzerAdapter):
    name = "semgrep"

    async def health(self) -> dict[str, Any]:
        executable = self.settings.resolved_tool("semgrep")
        rules = self.settings.semgrep_rules_path
        status = (
            CapabilityStatus.AVAILABLE
            if executable and rules.exists()
            else CapabilityStatus.NOT_CONFIGURED
        )
        return {
            "name": self.name,
            "status": status.value,
            "path": executable,
            "rules_path": str(rules),
            "rules_available": rules.exists(),
            "install_hint": "py -m pip install semgrep; 필요하면 MSW_SEMGREP_RULES_PATH 지정",
            "integration": "subprocess",
        }

    async def analyze(
        self,
        artifact_path: Path,
        output_dir: Path,
        *,
        platform: str,
        decompiled_dir: Path | None = None,
    ) -> AnalyzerResult:
        executable = self.settings.resolved_tool("semgrep")
        result = AnalyzerResult(self.name, CapabilityStatus.NOT_CONFIGURED)
        if not executable:
            result.error = "Semgrep 실행 파일을 찾을 수 없습니다."
            return result.finish()
        if not decompiled_dir or not decompiled_dir.is_dir():
            result.status = CapabilityStatus.NOT_CONFIGURED
            result.error = "JADX 디컴파일 결과가 없어 Semgrep을 실행하지 않았습니다."
            return result.finish()
        rules = self.settings.semgrep_rules_path
        if not rules.exists():
            result.error = f"Semgrep 규칙 경로가 없습니다: {rules}"
            return result.finish()
        command = [
            executable,
            "scan",
            "--json",
            "--metrics=off",
            "--timeout",
            "30",
            "--max-target-bytes",
            "3000000",
            "-c",
            str(rules),
            str(decompiled_dir),
        ]
        result.command = command
        executed = await run_command(
            command,
            timeout=300,
            memory_limit_mb=self.settings.external_tool_memory_mb,
            cpu_limit_seconds=self.settings.external_tool_cpu_seconds,
        )
        if executed.return_code not in {0, 1}:
            result.status = executed.status
            result.error = executed.error or executed.stderr.strip()[:1000]
            return result.finish()
        try:
            payload = json.loads(executed.stdout)
        except json.JSONDecodeError as exc:
            result.status = CapabilityStatus.FAILED
            result.error = f"Semgrep JSON 해석 실패: {exc}"
            result.save_raw(output_dir, {"stdout": executed.stdout, "stderr": executed.stderr})
            return result.finish()
        result.status = CapabilityStatus.AVAILABLE
        result.save_raw(output_dir, payload)
        for item in payload.get("results", []):
            extra = item.get("extra") or {}
            metadata = extra.get("metadata") or {}
            start = item.get("start") or {}
            path = str(item.get("path") or "decompiled source")
            location = f"{path}:{start.get('line', '?')}"
            result.findings.append(
                AnalyzerFinding(
                    title=str(extra.get("message") or item.get("check_id") or "Semgrep 탐지"),
                    category=str(metadata.get("category") or "code_pattern"),
                    severity=_severity(extra.get("severity"), "medium"),
                    location=location,
                    rationale=str(extra.get("message") or "코드 규칙과 일치했습니다."),
                    confidence=float(metadata.get("confidence_score", 0.72)),
                    source_tool=self.name,
                    rule_id=str(item.get("check_id") or "unknown"),
                    references={
                        "masvs": metadata.get("masvs"),
                        "mastg": metadata.get("mastg"),
                        "cwe": metadata.get("cwe"),
                    },
                    raw=item,
                )
            )
        result.metadata["result_count"] = len(result.findings)
        result.metadata["error_count"] = len(payload.get("errors", []))
        return result.finish()


class MobSFAnalyzerAdapter(AnalyzerAdapter):
    name = "mobsf"

    async def health(self) -> dict[str, Any]:
        if not self.settings.mobsf_url or not self.settings.mobsf_api_key:
            return {
                "name": self.name,
                "status": CapabilityStatus.NOT_CONFIGURED.value,
                "url": self.settings.mobsf_url,
                "install_hint": "MOBSF_URL과 MOBSF_API_KEY를 .env에 설정",
                "integration": "rest",
            }
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(
                    f"{self.settings.mobsf_url.rstrip('/')}/api/v1/scans",
                    headers={"Authorization": self.settings.mobsf_api_key},
                )
            return {
                "name": self.name,
                "status": (
                    CapabilityStatus.AVAILABLE.value
                    if response.is_success
                    else CapabilityStatus.FAILED.value
                ),
                "url": self.settings.mobsf_url,
                "http_status": response.status_code,
                "integration": "rest",
            }
        except httpx.HTTPError as exc:
            return {
                "name": self.name,
                "status": CapabilityStatus.FAILED.value,
                "url": self.settings.mobsf_url,
                "error": str(exc),
                "integration": "rest",
            }

    async def analyze(
        self,
        artifact_path: Path,
        output_dir: Path,
        *,
        platform: str,
        decompiled_dir: Path | None = None,
    ) -> AnalyzerResult:
        result = AnalyzerResult(self.name, CapabilityStatus.NOT_CONFIGURED)
        if not self.settings.mobsf_url or not self.settings.mobsf_api_key:
            result.error = "MobSF URL/API 키가 설정되지 않았습니다."
            return result.finish()
        base = self.settings.mobsf_url.rstrip("/")
        headers = {"Authorization": self.settings.mobsf_api_key}
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(360, connect=15)) as client:
                with artifact_path.open("rb") as stream:
                    upload = await client.post(
                        f"{base}/api/v1/upload",
                        headers=headers,
                        files={
                            "file": (
                                artifact_path.name,
                                stream,
                                "application/octet-stream",
                            )
                        },
                    )
                upload.raise_for_status()
                upload_data = upload.json()
                scan_payload = {
                    "hash": upload_data["hash"],
                    "scan_type": upload_data.get("scan_type", "apk" if platform == "android" else "ipa"),
                    "file_name": upload_data.get("file_name", artifact_path.name),
                    "re_scan": 1,
                }
                scan = await client.post(
                    f"{base}/api/v1/scan", headers=headers, data=scan_payload
                )
                scan.raise_for_status()
                payload = scan.json()
            result.status = CapabilityStatus.AVAILABLE
            result.command = ["POST", f"{base}/api/v1/upload", "→", "/api/v1/scan"]
            result.metadata = {
                "hash": upload_data.get("hash"),
                "scan_type": upload_data.get("scan_type"),
            }
            result.save_raw(output_dir, payload)
            result.findings.extend(self._normalize(payload, platform))
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            result.status = CapabilityStatus.FAILED
            result.error = f"{type(exc).__name__}: {exc}"
        return result.finish()

    def _normalize(self, payload: dict[str, Any], platform: str) -> list[AnalyzerFinding]:
        findings: list[AnalyzerFinding] = []
        groups = ("manifest_analysis", "code_analysis", "binary_analysis")
        for group_name in groups:
            group = payload.get(group_name)
            if not isinstance(group, dict):
                continue
            candidates = group.get("findings", group)
            if not isinstance(candidates, dict):
                continue
            for rule_id, item in list(candidates.items())[:1000]:
                if not isinstance(item, dict):
                    continue
                metadata = item.get("metadata") or {}
                title = metadata.get("description") or item.get("title") or rule_id
                files = item.get("files") or item.get("file") or []
                if isinstance(files, dict):
                    location = ", ".join(list(files)[:5])
                elif isinstance(files, list):
                    location = ", ".join(str(value) for value in files[:5])
                else:
                    location = str(files or group_name)
                severity = _severity(
                    metadata.get("severity") or item.get("severity"), "info"
                )
                findings.append(
                    AnalyzerFinding(
                        title=str(title)[:300],
                        category=str(metadata.get("category") or group_name),
                        severity=severity,
                        location=location[:1000],
                        rationale=str(
                            metadata.get("description")
                            or item.get("description")
                            or title
                        )[:4000],
                        confidence=0.78 if severity in {"high", "medium"} else 0.65,
                        source_tool=self.name,
                        rule_id=str(rule_id),
                        references={
                            "masvs": metadata.get("masvs"),
                            "cwe": metadata.get("cwe"),
                            "platform": platform,
                        },
                        raw=item,
                    )
                )
        return findings
