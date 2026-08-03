from __future__ import annotations

import hashlib
import asyncio
import ipaddress
import json
import os
import plistlib
import re
import shutil
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from backend.app.core.command import run_command
from backend.app.core.config import AppSettings, get_settings
from backend.app.core.status import CapabilityStatus
from backend.app.catalog import CATALOG_SOURCE, evaluate_controls
from backend.app.analyzers.adapters import (
    APKiDAnalyzerAdapter,
    AndroguardAnalyzerAdapter,
    MobSFAnalyzerAdapter,
    SemgrepAnalyzerAdapter,
)
from backend.app.analyzers.base import AnalyzerResult, finding_fingerprint


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
TEXT_EXTENSIONS = {
    ".xml",
    ".json",
    ".txt",
    ".js",
    ".java",
    ".kt",
    ".smali",
    ".properties",
    ".plist",
    ".strings",
    ".html",
}
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_SCAN_BYTES = 40 * 1024 * 1024


@dataclass(slots=True)
class Candidate:
    kind: str
    value: str
    location: str
    severity: str = "info"
    masked_value: str | None = None


@dataclass(slots=True)
class StaticFinding:
    title: str
    category: str
    severity: str
    location: str
    rationale: str
    confidence: float
    verdict: str = "needs_review"
    source_tool: str = "native_static"
    rule_id: str = "heuristic"
    references: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        return finding_fingerprint(
            self.source_tool,
            self.rule_id,
            self.category,
            self.location,
            self.title,
        )


@dataclass(slots=True)
class StaticAnalysisResult:
    status: str
    platform: str
    sha256: str
    file_size: int
    app_name: str | None = None
    package_name: str | None = None
    version: str | None = None
    structure: dict[str, Any] = field(default_factory=dict)
    manifest: dict[str, Any] = field(default_factory=dict)
    permissions: list[str] = field(default_factory=list)
    entitlements: dict[str, Any] = field(default_factory=dict)
    components: list[dict[str, Any]] = field(default_factory=list)
    deep_links: list[dict[str, Any]] = field(default_factory=list)
    native_libraries: list[str] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)
    signals: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    findings: list[StaticFinding] = field(default_factory=list)
    tools: dict[str, dict[str, Any]] = field(default_factory=dict)
    tool_runs: list[dict[str, Any]] = field(default_factory=list)
    controls: list[dict[str, Any]] = field(default_factory=list)
    catalog_source: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for index, finding in enumerate(self.findings):
            data["findings"][index]["fingerprint"] = finding.fingerprint
        return data


class StaticAnalyzer:
    def __init__(self, settings: AppSettings | None = None):
        self.settings = settings or get_settings()

    @staticmethod
    def detect_platform(path: Path) -> str:
        extension = path.suffix.lower()
        if extension == ".apk":
            return "android"
        if extension == ".ipa":
            return "ios"
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                names = archive.namelist()
                if "AndroidManifest.xml" in names:
                    return "android"
                if any(
                    name.startswith("Payload/") and name.endswith(".app/Info.plist")
                    for name in names
                ):
                    return "ios"
        raise ValueError("APK 또는 IPA 파일만 분석할 수 있습니다.")

    @staticmethod
    def _hash(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _tool_info(self, name: str) -> dict[str, Any]:
        configured = getattr(self.settings.tools, name)
        resolved = self.settings.resolved_tool(name)
        hints = {
            "apktool": "winget install --id iBotPeaches.Apktool 또는 apktool 공식 Windows 설치 절차",
            "jadx": "winget install --id skylot.jadx 또는 jadx 릴리스 압축 해제",
            "aapt": "Android SDK Build-Tools 설치 후 aapt.exe 경로 지정",
            "apkanalyzer": "Android SDK Command-line Tools 설치 후 apkanalyzer.bat 경로 지정",
        }
        return {
            "status": (
                CapabilityStatus.AVAILABLE.value
                if resolved
                else CapabilityStatus.NOT_CONFIGURED.value
            ),
            "configured_path": configured,
            "resolved_path": resolved,
            "install_hint": hints.get(name, "설정 화면에서 실행 파일 경로 지정"),
        }

    async def analyze(self, path: Path, output_dir: Path | None = None) -> StaticAnalysisResult:
        analysis_started = datetime.now(timezone.utc)
        platform = self.detect_platform(path)
        result = StaticAnalysisResult(
            status="running",
            platform=platform,
            sha256=self._hash(path),
            file_size=path.stat().st_size,
            tools={
                name: self._tool_info(name)
                for name in (
                    "apktool",
                    "jadx",
                    "aapt",
                    "apkanalyzer",
                    "apkid",
                    "semgrep",
                )
            },
        )
        if not zipfile.is_zipfile(path):
            result.status = "failed"
            result.warnings.append("파일이 유효한 ZIP 기반 APK/IPA가 아닙니다.")
            return result

        with zipfile.ZipFile(path) as archive:
            self._analyze_structure(archive, result)
            if platform == "android":
                self._analyze_android_archive(archive, result)
            else:
                self._analyze_ios_archive(archive, result)
            self._scan_archive(archive, result)

        if platform == "android":
            await self._run_androguard(path, output_dir, result)
            await self._enrich_android_with_tools(path, output_dir, result)
            await self._run_external_analyzers(path, output_dir, result)
        else:
            await self._run_mobsf(path, output_dir, result)

        self._derive_findings(result)
        self._deduplicate_findings(result)
        result.controls = evaluate_controls(result.platform, result.to_dict())
        result.catalog_source = CATALOG_SOURCE
        analysis_finished = datetime.now(timezone.utc)
        native_count = sum(
            1 for item in result.findings if item.source_tool == "native_static"
        )
        result.tool_runs.insert(
            0,
            {
                "tool": "native_static",
                "status": "available",
                "version": "0.2.0",
                "command": [],
                "started_at": analysis_started.isoformat(),
                "finished_at": analysis_finished.isoformat(),
                "raw_output_path": None,
                "raw_sha256": None,
                "error": None,
                "finding_count": native_count,
                "metadata": {
                    "scanned_bytes": result.structure.get("scanned_bytes", 0),
                    "candidate_count": len(result.candidates),
                },
            },
        )
        result.tools["native_static"] = {
            "status": "available",
            "version": "0.2.0",
            "finding_count": native_count,
        }
        result.status = "completed"
        return result

    async def _run_androguard(
        self,
        path: Path,
        output_dir: Path | None,
        result: StaticAnalysisResult,
    ) -> None:
        adapter = AndroguardAnalyzerAdapter(self.settings)
        execution = await adapter.analyze(
            path,
            (output_dir or self.settings.analysis_dir / result.sha256[:12]) / "tools",
            platform=result.platform,
        )
        self._merge_adapter_result(result, execution)
        enrichment = execution.enrichment
        manifest_text = enrichment.get("manifest_text")
        if manifest_text and (
            result.manifest.get("format") == "binary_axml" or not result.package_name
        ):
            try:
                result.components.clear()
                result.deep_links.clear()
                self._parse_android_manifest(manifest_text, result)
                result.manifest["parser"] = "androguard"
            except ET.ParseError as exc:
                result.warnings.append(f"Androguard Manifest 정규화 실패: {exc}")
        result.package_name = result.package_name or enrichment.get("package_name")
        result.app_name = result.app_name or enrichment.get("app_name")
        result.version = result.version or enrichment.get("version")

    async def _run_external_analyzers(
        self,
        path: Path,
        output_dir: Path | None,
        result: StaticAnalysisResult,
    ) -> None:
        tool_dir = (output_dir or self.settings.analysis_dir / result.sha256[:12]) / "tools"
        decompiled = result.structure.get("decompiled_path")
        decompiled_dir = Path(decompiled) if decompiled else None
        adapters = (
            APKiDAnalyzerAdapter(self.settings),
            SemgrepAnalyzerAdapter(self.settings),
            MobSFAnalyzerAdapter(self.settings),
        )
        executions = await asyncio.gather(
            *(
                adapter.analyze(
                    path,
                    tool_dir,
                    platform=result.platform,
                    decompiled_dir=decompiled_dir,
                )
                for adapter in adapters
            )
        )
        for execution in executions:
            self._merge_adapter_result(result, execution)

    async def _run_mobsf(
        self,
        path: Path,
        output_dir: Path | None,
        result: StaticAnalysisResult,
    ) -> None:
        execution = await MobSFAnalyzerAdapter(self.settings).analyze(
            path,
            (output_dir or self.settings.analysis_dir / result.sha256[:12]) / "tools",
            platform=result.platform,
        )
        self._merge_adapter_result(result, execution)

    @staticmethod
    def _merge_adapter_result(
        result: StaticAnalysisResult, execution: AnalyzerResult
    ) -> None:
        result.tool_runs.append(execution.to_dict())
        result.tools[execution.tool] = {
            "status": execution.status.value,
            "version": execution.version,
            "last_status": execution.status.value,
            "last_command": " ".join(execution.command),
            "raw_output_path": execution.raw_output_path,
            "finding_count": len(execution.findings),
            "error": execution.error,
        }
        for item in execution.findings:
            result.findings.append(
                StaticFinding(
                    title=item.title,
                    category=item.category,
                    severity=item.severity,
                    location=item.location,
                    rationale=item.rationale,
                    confidence=item.confidence,
                    verdict=item.verdict,
                    source_tool=item.source_tool,
                    rule_id=item.rule_id,
                    references=item.references,
                    raw=item.raw,
                )
            )

    @staticmethod
    def _deduplicate_findings(result: StaticAnalysisResult) -> None:
        unique: dict[str, StaticFinding] = {}
        for finding in result.findings:
            current = unique.get(finding.fingerprint)
            if not current or finding.confidence > current.confidence:
                unique[finding.fingerprint] = finding
        result.findings = list(unique.values())

    def _analyze_structure(
        self, archive: zipfile.ZipFile, result: StaticAnalysisResult
    ) -> None:
        infos = archive.infolist()
        total_uncompressed = sum(info.file_size for info in infos)
        result.structure = {
            "entry_count": len(infos),
            "compressed_bytes": sum(info.compress_size for info in infos),
            "uncompressed_bytes": total_uncompressed,
            "has_manifest": "AndroidManifest.xml" in archive.namelist()
            if result.platform == "android"
            else any(name.endswith(".app/Info.plist") for name in archive.namelist()),
            "dex_files": sorted(
                name for name in archive.namelist() if re.search(r"classes\d*\.dex$", name)
            ),
            "architectures": sorted(
                {
                    PurePosixPath(name).parts[1]
                    for name in archive.namelist()
                    if name.startswith("lib/") and len(PurePosixPath(name).parts) > 2
                }
            ),
        }
        result.native_libraries = sorted(
            name
            for name in archive.namelist()
            if name.lower().endswith((".so", ".dylib"))
        )
        if total_uncompressed > 2 * 1024 * 1024 * 1024:
            result.warnings.append("압축 해제 크기가 2GB를 넘어 도구 기반 디컴파일을 생략할 수 있습니다.")

    def _analyze_android_archive(
        self, archive: zipfile.ZipFile, result: StaticAnalysisResult
    ) -> None:
        try:
            data = archive.read("AndroidManifest.xml")
        except KeyError:
            result.warnings.append("AndroidManifest.xml이 없습니다.")
            return
        try:
            text = data.decode("utf-8")
            self._parse_android_manifest(text, result)
        except (UnicodeDecodeError, ET.ParseError):
            result.manifest["format"] = "binary_axml"
            result.warnings.append(
                "Manifest가 바이너리 AXML입니다. 상세 해석에는 apktool/aapt가 필요합니다."
            )

    def _parse_android_manifest(
        self, manifest_text: str, result: StaticAnalysisResult
    ) -> None:
        root = ET.fromstring(manifest_text)
        result.package_name = root.attrib.get("package")
        result.version = root.attrib.get(f"{ANDROID_NS}versionName")
        result.permissions = sorted(
            {
                node.attrib.get(f"{ANDROID_NS}name", "")
                for node in root.findall("uses-permission")
                if node.attrib.get(f"{ANDROID_NS}name")
            }
        )
        application = root.find("application")
        if application is None:
            return
        result.app_name = application.attrib.get(f"{ANDROID_NS}label")
        result.manifest.update(
            {
                "format": "text_xml",
                "debuggable": self._bool_attr(application, "debuggable"),
                "allow_backup": self._bool_attr(application, "allowBackup"),
                "uses_cleartext_traffic": self._bool_attr(
                    application, "usesCleartextTraffic"
                ),
                "network_security_config": application.attrib.get(
                    f"{ANDROID_NS}networkSecurityConfig"
                ),
                "extract_native_libs": self._bool_attr(
                    application, "extractNativeLibs"
                ),
            }
        )
        for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            for node in application.findall(tag):
                name = node.attrib.get(f"{ANDROID_NS}name", "unknown")
                filters = node.findall("intent-filter")
                exported_raw = node.attrib.get(f"{ANDROID_NS}exported")
                exported = (
                    exported_raw.lower() == "true"
                    if exported_raw is not None
                    else bool(filters)
                )
                component = {
                    "type": tag,
                    "name": name,
                    "exported": exported,
                    "permission": node.attrib.get(f"{ANDROID_NS}permission"),
                    "intent_filters": len(filters),
                }
                result.components.append(component)
                for intent_filter in filters:
                    actions = [
                        item.attrib.get(f"{ANDROID_NS}name")
                        for item in intent_filter.findall("action")
                    ]
                    categories = [
                        item.attrib.get(f"{ANDROID_NS}name")
                        for item in intent_filter.findall("category")
                    ]
                    for data in intent_filter.findall("data"):
                        link = {
                            "component": name,
                            "scheme": data.attrib.get(f"{ANDROID_NS}scheme"),
                            "host": data.attrib.get(f"{ANDROID_NS}host"),
                            "path": data.attrib.get(f"{ANDROID_NS}path")
                            or data.attrib.get(f"{ANDROID_NS}pathPrefix"),
                            "actions": [value for value in actions if value],
                            "categories": [value for value in categories if value],
                        }
                        if link["scheme"] or link["host"]:
                            result.deep_links.append(link)

    @staticmethod
    def _bool_attr(node: ET.Element, name: str) -> bool | None:
        value = node.attrib.get(f"{ANDROID_NS}{name}")
        if value is None:
            return None
        return value.lower() == "true"

    def _analyze_ios_archive(
        self, archive: zipfile.ZipFile, result: StaticAnalysisResult
    ) -> None:
        info_names = sorted(
            name
            for name in archive.namelist()
            if name.startswith("Payload/") and name.endswith(".app/Info.plist")
        )
        if not info_names:
            result.warnings.append("Payload/*.app/Info.plist가 없습니다.")
            return
        try:
            plist = plistlib.loads(archive.read(info_names[0]))
        except (plistlib.InvalidFileException, ValueError) as exc:
            result.warnings.append(f"Info.plist 해석 실패: {exc}")
            return
        result.app_name = plist.get("CFBundleDisplayName") or plist.get("CFBundleName")
        result.package_name = plist.get("CFBundleIdentifier")
        result.version = plist.get("CFBundleShortVersionString")
        result.manifest = {
            "format": "plist",
            "ats": plist.get("NSAppTransportSecurity", {}),
            "file_sharing_enabled": plist.get("UIFileSharingEnabled"),
            "supports_document_browser": plist.get("UISupportsDocumentBrowser"),
            "background_modes": plist.get("UIBackgroundModes", []),
        }
        for entry in plist.get("CFBundleURLTypes", []):
            for scheme in entry.get("CFBundleURLSchemes", []):
                result.deep_links.append(
                    {
                        "scheme": scheme,
                        "name": entry.get("CFBundleURLName"),
                        "role": entry.get("CFBundleTypeRole"),
                    }
                )
        associated = plist.get("com.apple.developer.associated-domains", [])
        if associated:
            result.entitlements["associated_domains"] = associated

    def _scan_archive(
        self, archive: zipfile.ZipFile, result: StaticAnalysisResult
    ) -> None:
        scanned = 0
        seen_candidates: set[tuple[str, str, str]] = set()
        signals: dict[str, list[dict[str, str]]] = {
            "webview": [],
            "javascript_interface": [],
            "local_storage": [],
            "crypto": [],
            "certificate_pinning": [],
            "root_jailbreak_detection": [],
            "frida_hook_detection": [],
            "debugger_detection": [],
            "integrity_signature": [],
            "obfuscation": [],
        }
        patterns = {
            "webview": re.compile(r"\b(?:WebView|WKWebView|setJavaScriptEnabled)\b", re.I),
            "javascript_interface": re.compile(
                r"\b(?:addJavascriptInterface|WKScriptMessageHandler)\b", re.I
            ),
            "local_storage": re.compile(
                r"\b(?:SharedPreferences|SQLiteDatabase|RoomDatabase|UserDefaults|NSUserDefaults|Keychain|SecItemAdd|openFileOutput)\b",
                re.I,
            ),
            "crypto": re.compile(
                r"\b(?:AES|DESede|DES|RSA|Cipher\.getInstance|CCCrypt|SecKeyCreate)\b",
                re.I,
            ),
            "certificate_pinning": re.compile(
                r"\b(?:CertificatePinner|TrustManager|HostnameVerifier|X509TrustManager|SecTrustEvaluate|serverTrust|pinning)\b",
                re.I,
            ),
            "root_jailbreak_detection": re.compile(
                r"(?:/system/xbin/su|/system/bin/su|/Applications/Cydia\.app|jailbreak|magisk|busybox|rootbeer)",
                re.I,
            ),
            "frida_hook_detection": re.compile(
                r"\b(?:frida|gum-js-loop|xposed|substrate|ptrace)\b", re.I
            ),
            "debugger_detection": re.compile(
                r"\b(?:isDebuggerConnected|TracerPid|PT_DENY_ATTACH|Debug\.waitForDebugger)\b",
                re.I,
            ),
            "integrity_signature": re.compile(
                r"\b(?:getPackageInfo|GET_SIGNING_CERTIFICATES|MessageDigest|SecCodeCheckValidity|signature|integrity)\b",
                re.I,
            ),
            "obfuscation": re.compile(r"\b(?:proguard|dexguard|allatori|classguard)\b", re.I),
        }
        for info in archive.infolist():
            if info.is_dir() or info.file_size > MAX_MEMBER_BYTES or scanned >= MAX_SCAN_BYTES:
                continue
            suffix = PurePosixPath(info.filename).suffix.lower()
            if suffix not in TEXT_EXTENSIONS and suffix not in {".dex", ".so", ""}:
                continue
            try:
                data = archive.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile):
                continue
            scanned += len(data)
            text = data.decode("utf-8", errors="ignore")
            if suffix in {".dex", ".so"}:
                text = "\n".join(
                    match.decode("utf-8", errors="ignore")
                    for match in re.findall(rb"[\x20-\x7e]{6,}", data)
                )
            for candidate in self._extract_candidates(text, info.filename):
                key = (candidate.kind, candidate.value, candidate.location)
                if key not in seen_candidates:
                    result.candidates.append(candidate)
                    seen_candidates.add(key)
            for key, pattern in patterns.items():
                for match in list(pattern.finditer(text))[:5]:
                    excerpt = text[max(0, match.start() - 50) : match.end() + 80]
                    signals[key].append(
                        {
                            "location": info.filename,
                            "match": match.group(0),
                            "excerpt": " ".join(excerpt.split())[:240],
                        }
                    )
                    if len(signals[key]) >= 30:
                        break
        result.signals = {key: values for key, values in signals.items() if values}
        result.structure["scanned_bytes"] = scanned

    def _extract_candidates(self, text: str, location: str) -> Iterable[Candidate]:
        url_pattern = re.compile(r"https?://[^\s\"'<>\\]{4,500}", re.I)
        ip_pattern = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
        secret_patterns = {
            "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),
            "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
            "generic_api_key": re.compile(
                r"(?i)\b(?:api[_-]?key|secret|token)\b\s*[:=]\s*[\"']([A-Za-z0-9_./+=-]{12,})[\"']"
            ),
            "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        }
        for match in url_pattern.finditer(text):
            value = match.group(0).rstrip(".,);]")
            yield Candidate("url", value, location, "info", self._mask(value))
        for match in ip_pattern.finditer(text):
            value = match.group(0)
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if not address.is_unspecified:
                yield Candidate("ip", value, location, "low", self._mask(value))
        for kind, pattern in secret_patterns.items():
            for match in pattern.finditer(text):
                value = match.group(1) if match.lastindex else match.group(0)
                severity = "high" if kind in {"private_key", "aws_access_key"} else "medium"
                yield Candidate(kind, value, location, severity, self._mask(value))

    @staticmethod
    def _mask(value: str) -> str:
        if len(value) <= 8:
            return "*" * len(value)
        return f"{value[:4]}…{value[-4:]}"

    async def _enrich_android_with_tools(
        self,
        path: Path,
        output_dir: Path | None,
        result: StaticAnalysisResult,
    ) -> None:
        apktool = self.settings.resolved_tool("apktool")
        aapt = self.settings.resolved_tool("aapt")
        if result.manifest.get("format") == "binary_axml" and apktool:
            parent = output_dir or self.settings.data_dir / "analysis" / result.sha256[:12]
            decoded_dir = parent / "apktool"
            decoded_dir.parent.mkdir(parents=True, exist_ok=True)
            command = await run_command(
                [apktool, "d", "-f", "-s", str(path), "-o", str(decoded_dir)],
                timeout=180,
            )
            result.tools["apktool"]["last_status"] = command.status.value
            result.tools["apktool"]["last_command"] = command.display_command
            decoded_manifest = decoded_dir / "AndroidManifest.xml"
            if command.ok and decoded_manifest.is_file():
                try:
                    self._parse_android_manifest(
                        decoded_manifest.read_text(encoding="utf-8"), result
                    )
                    result.structure["decoded_path"] = str(decoded_dir)
                except (OSError, ET.ParseError) as exc:
                    result.warnings.append(f"apktool Manifest 해석 실패: {exc}")
            elif not command.ok:
                result.warnings.append(
                    f"apktool 실행 실패: {command.error or command.stderr.strip()}"
                )
        elif result.manifest.get("format") == "binary_axml" and aapt:
            command = await run_command(
                [aapt, "dump", "badging", str(path)],
                timeout=60,
            )
            result.tools["aapt"]["last_status"] = command.status.value
            if command.ok:
                package = re.search(
                    r"package: name='([^']+)' versionCode='[^']*' versionName='([^']*)'",
                    command.stdout,
                )
                application = re.search(r"application-label:'([^']*)'", command.stdout)
                if package:
                    result.package_name, result.version = package.groups()
                if application:
                    result.app_name = application.group(1)

        jadx = self.settings.resolved_tool("jadx")
        if jadx and output_dir and result.file_size < 300 * 1024 * 1024:
            jadx_dir = output_dir / "jadx"
            command = await run_command(
                [jadx, "--no-res", "-d", str(jadx_dir), str(path)],
                timeout=300,
            )
            result.tools["jadx"]["last_status"] = command.status.value
            result.tools["jadx"]["last_command"] = command.display_command
            if command.ok:
                result.structure["decompiled_path"] = str(jadx_dir)
            else:
                result.warnings.append(
                    f"jadx 실행 실패: {command.error or command.stderr.strip()[:500]}"
                )

    def _derive_findings(self, result: StaticAnalysisResult) -> None:
        if result.platform == "android":
            if result.manifest.get("debuggable") is True:
                result.findings.append(
                    StaticFinding(
                        "디버그 가능 빌드 설정",
                        "build_configuration",
                        "high",
                        "AndroidManifest.xml / application",
                        "android:debuggable=true가 설정되어 런타임 디버깅 노출 가능성이 있습니다.",
                        0.98,
                        "confirmed",
                    )
                )
            if result.manifest.get("allow_backup") is True:
                result.findings.append(
                    StaticFinding(
                        "애플리케이션 백업 허용",
                        "data_protection",
                        "medium",
                        "AndroidManifest.xml / application",
                        "android:allowBackup=true가 명시되어 앱 데이터 백업 가능성을 확인해야 합니다.",
                        0.85,
                    )
                )
            exported = [
                item for item in result.components if item["exported"] and not item["permission"]
            ]
            if exported:
                result.findings.append(
                    StaticFinding(
                        "권한 보호가 없는 외부 노출 컴포넌트",
                        "exposed_component",
                        "medium",
                        ", ".join(item["name"] for item in exported[:8]),
                        f"외부 호출 가능 컴포넌트 {len(exported)}개가 권한으로 보호되지 않은 것으로 보입니다.",
                        0.78,
                    )
                )
        elif result.manifest.get("ats", {}).get("NSAllowsArbitraryLoads") is True:
            result.findings.append(
                StaticFinding(
                    "ATS 전체 예외 허용",
                    "transport_security",
                    "high",
                    "Info.plist / NSAppTransportSecurity",
                    "NSAllowsArbitraryLoads가 활성화되어 평문 또는 약한 전송 설정을 허용할 수 있습니다.",
                    0.96,
                    "confirmed",
                )
            )

        secret_candidates = [
            item
            for item in result.candidates
            if item.kind not in {"url", "ip"}
        ]
        if secret_candidates:
            result.findings.append(
                StaticFinding(
                    "하드코딩 민감정보 후보",
                    "hardcoded_secret",
                    "high",
                    ", ".join(sorted({item.location for item in secret_candidates})[:8]),
                    f"API 키·토큰·개인키 패턴과 일치하는 문자열 {len(secret_candidates)}개가 있습니다. 실제 유효성은 수동 확인이 필요합니다.",
                    0.72,
                )
            )
        if result.signals.get("javascript_interface"):
            result.findings.append(
                StaticFinding(
                    "WebView JavaScript 인터페이스 사용",
                    "webview",
                    "medium",
                    result.signals["javascript_interface"][0]["location"],
                    "네이티브 JavaScript 인터페이스가 탐지되었습니다. 로드 URL과 노출 메서드 검토가 필요합니다.",
                    0.74,
                )
            )
        if result.signals.get("certificate_pinning"):
            result.findings.append(
                StaticFinding(
                    "인증서 고정 구현 후보",
                    "security_control",
                    "info",
                    result.signals["certificate_pinning"][0]["location"],
                    "인증서 고정 또는 사용자 정의 신뢰 검증 코드가 탐지되었습니다. 동적 검증 대상으로 연결합니다.",
                    0.68,
                    "informational",
                )
            )
        if result.signals.get("root_jailbreak_detection"):
            result.findings.append(
                StaticFinding(
                    "루팅·탈옥 탐지 코드 후보",
                    "security_control",
                    "info",
                    result.signals["root_jailbreak_detection"][0]["location"],
                    "특권 단말 탐지에 사용되는 경로 또는 프레임워크 신호가 있습니다.",
                    0.7,
                    "informational",
                )
            )
