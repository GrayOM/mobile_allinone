"""Server TLS configuration check for the HTTPS items of the domestic profile.

The workbench calls ``sslyze`` (AGPL-3.0) as an optional subprocess and never
imports it, so the licence boundary matches the other copyleft integrations.
Only hosts inside the Run's approved control-validation scope are scanned.

Decision rules follow the customer advisory (EFI-MA-41~44):

* EFI-MA-41 · SSL 3.0 이하 또는 TLS 1.2 미만 프로토콜 허용 → 취약
* EFI-MA-42 · INSECURE 등급 암호(NULL·EXPORT·익명·RC4·단일 DES·RC2·MD5 MAC) 허용 → 취약.
  3DES·CBC·정적 RSA는 문서가 WEAK(양호)로 보므로 관찰 정보로만 남긴다.
* EFI-MA-43 · Heartbleed, OpenSSL CCS Injection, SSLv3 허용(POODLE), EXPORT RSA(FREAK) → 취약.
  ROBOT·TLS 압축은 문서 판정 대상이 아니므로 관찰 정보로 남긴다.
* EFI-MA-44 · 안전한 재협상 미지원 상태에서 클라이언트 재협상 허용 → 취약.

The scanner output is raw evidence; nothing here sends application traffic or
changes server state beyond the TLS handshakes sslyze performs.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from backend.app.control_validation import (
    ControlScopeError,
    network_host_allowed,
    normalize_network_host,
)
from backend.app.core.command import run_command
from backend.app.core.config import AppSettings
from backend.app.core.status import CapabilityStatus

TLS_CONTROL_IDS = ("EFI-MA-41", "EFI-MA-42", "EFI-MA-43", "EFI-MA-44")
MAX_TARGETS = 5
SCAN_TIMEOUT_SECONDS = 240

PROTOCOL_KEYS: tuple[tuple[str, str], ...] = (
    ("ssl_2_0_cipher_suites", "SSL 2.0"),
    ("ssl_3_0_cipher_suites", "SSL 3.0"),
    ("tls_1_0_cipher_suites", "TLS 1.0"),
    ("tls_1_1_cipher_suites", "TLS 1.1"),
    ("tls_1_2_cipher_suites", "TLS 1.2"),
    ("tls_1_3_cipher_suites", "TLS 1.3"),
)
WEAK_PROTOCOLS = {"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"}

_INSECURE_CIPHER = re.compile(
    r"(?:_NULL_|_WITH_NULL|EXPORT|_EXP_|_anon_|^ADH|^AECDH|RC4|RC2|_MD5$|"
    r"_WITH_DES_CBC_|_DES40_|_WITH_DES_|^DES-CBC-)",
    re.I,
)
_EXPORT_RSA = re.compile(r"EXPORT.*RSA|RSA.*EXPORT|^EXP-", re.I)
_WEAK_CIPHER = re.compile(r"3DES|DES_EDE|DES-CBC3|_CBC_", re.I)


class TlsScanError(ValueError):
    def __init__(self, message: str, status_code: int = 422):
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class TlsTarget:
    host: str
    port: int
    pinned_ip: str | None = None

    @property
    def display(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"

    @property
    def sslyze_target(self) -> str:
        """sslyze ``host:port{ip}`` form pins the address resolved by the workbench."""
        if self.pinned_ip and self.pinned_ip != self.host:
            return f"{self.display}{{{self.pinned_ip}}}"
        return self.display


@dataclass(slots=True)
class TlsScanOutcome:
    status: CapabilityStatus
    message: str
    command: str = ""
    raw_path: Path | None = None
    servers: list[dict[str, Any]] = field(default_factory=list)
    control_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    sslyze_version: str | None = None
    synthetic: bool = False


TLS_ANY_KEY = "TLS-ANY"


async def pin_targets(targets: list[TlsTarget]) -> list[TlsTarget]:
    """Resolve each approved hostname once and pin sslyze to that address.

    Without pinning, sslyze would resolve DNS on its own and a rebinding answer
    could point the TLS probes at an address the approval never covered.
    """
    loop = asyncio.get_running_loop()
    pinned: list[TlsTarget] = []
    for target in targets:
        try:
            literal = ipaddress.ip_address(target.host)
        except ValueError:
            literal = None
        if literal is not None:
            pinned.append(TlsTarget(target.host, target.port, str(literal)))
            continue
        try:
            records = await asyncio.wait_for(
                loop.getaddrinfo(
                    target.host,
                    target.port,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM,
                ),
                timeout=5,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            raise TlsScanError(f"승인 대상 DNS 해석 실패: {target.host}: {exc}", 409) from exc
        addresses = sorted({ipaddress.ip_address(record[4][0]) for record in records}, key=str)
        usable = [
            address
            for address in addresses
            if not (
                address.is_loopback
                or address.is_link_local
                or address.is_multicast
                or address.is_unspecified
                or address.is_reserved
            )
        ]
        if not usable:
            raise TlsScanError(
                f"승인 대상 {target.host}이(가) 점검할 수 없는 주소로 해석되었습니다.", 409
            )
        pinned.append(TlsTarget(target.host, target.port, str(usable[0])))
    return pinned


def parse_targets(
    values: Iterable[str], allowed_hosts: list[str] | None
) -> list[TlsTarget]:
    """Validate ``host[:port]`` entries against the approved host list.

    ``allowed_hosts=None`` is used only for Mock projects whose scan is
    synthetic and never opens a socket.
    """
    targets: list[TlsTarget] = []
    for raw in values:
        text = str(raw or "").strip()
        if not text:
            continue
        if "://" in text or "/" in text or "@" in text or "*" in text:
            raise TlsScanError(f"대상은 host 또는 host:port 형식이어야 합니다: {text[:80]}")
        host, port = text, 443
        if text.startswith("["):
            closing = text.find("]")
            if closing < 0:
                raise TlsScanError(f"IPv6 대상 형식이 올바르지 않습니다: {text[:80]}")
            host = text[1:closing]
            rest = text[closing + 1 :]
            if rest:
                if not rest.startswith(":") or not rest[1:].isdigit():
                    raise TlsScanError(f"포트 형식이 올바르지 않습니다: {text[:80]}")
                port = int(rest[1:])
        elif text.count(":") == 1:
            host, port_text = text.split(":", 1)
            if not port_text.isdigit():
                raise TlsScanError(f"포트 형식이 올바르지 않습니다: {text[:80]}")
            port = int(port_text)
        if not 1 <= port <= 65535:
            raise TlsScanError(f"포트 범위가 올바르지 않습니다: {text[:80]}")
        try:
            normalized = normalize_network_host(host)
        except ControlScopeError as exc:
            raise TlsScanError(str(exc)) from exc
        if allowed_hosts is not None and not network_host_allowed(normalized, allowed_hosts):
            raise TlsScanError(
                f"승인된 테스트 서버 범위 밖의 대상입니다: {normalized}", 403
            )
        try:
            address = ipaddress.ip_address(normalized)
        except ValueError:
            address = None
        if address is not None and (address.is_multicast or address.is_unspecified):
            raise TlsScanError(f"점검할 수 없는 주소입니다: {normalized}")
        target = TlsTarget(normalized, port)
        if target not in targets:
            targets.append(target)
    if not targets:
        raise TlsScanError("점검할 대상 서버를 1개 이상 입력하세요.")
    if len(targets) > MAX_TARGETS:
        raise TlsScanError(f"한 번에 최대 {MAX_TARGETS}개 서버만 점검할 수 있습니다.")
    return targets


def _accepted(section: Any) -> list[str]:
    if not isinstance(section, dict) or section.get("status") != "COMPLETED":
        return []
    result = section.get("result") or {}
    names: list[str] = []
    for item in result.get("accepted_cipher_suites") or []:
        suite = item.get("cipher_suite") if isinstance(item, dict) else None
        if isinstance(suite, dict) and suite.get("name"):
            names.append(str(suite["name"]))
    return names


def _plugin_result(scan_result: dict[str, Any], key: str) -> dict[str, Any] | None:
    section = scan_result.get(key)
    if not isinstance(section, dict) or section.get("status") != "COMPLETED":
        return None
    result = section.get("result")
    return result if isinstance(result, dict) else None


def summarize_server(server: dict[str, Any]) -> dict[str, Any]:
    location = server.get("server_location") or {}
    summary: dict[str, Any] = {
        "host": location.get("hostname"),
        "port": location.get("port"),
        "ip_address": location.get("ip_address"),
        "connectivity_status": server.get("connectivity_status"),
        "scan_status": server.get("scan_status"),
        "protocols": {},
        "weak_protocols": [],
        "insecure_ciphers": [],
        "export_rsa_ciphers": [],
        "weak_ciphers": [],
        "incomplete_checks": [],
    }
    scan_result = server.get("scan_result")
    if server.get("scan_status") != "COMPLETED" or not isinstance(scan_result, dict):
        summary["incomplete_checks"].append("connectivity")
        return summary
    for key, label in PROTOCOL_KEYS:
        section = scan_result.get(key)
        if not isinstance(section, dict) or section.get("status") != "COMPLETED":
            summary["incomplete_checks"].append(key)
            continue
        accepted = _accepted(section)
        summary["protocols"][label] = bool(accepted)
        if accepted and label in WEAK_PROTOCOLS:
            summary["weak_protocols"].append(label)
        for name in accepted:
            entry = f"{label} · {name}"
            if _INSECURE_CIPHER.search(name):
                summary["insecure_ciphers"].append(entry)
                if _EXPORT_RSA.search(name):
                    summary["export_rsa_ciphers"].append(entry)
            elif _WEAK_CIPHER.search(name):
                summary["weak_ciphers"].append(entry)
    reneg = _plugin_result(scan_result, "session_renegotiation")
    if reneg is None:
        summary["incomplete_checks"].append("session_renegotiation")
    summary["renegotiation"] = {
        "supports_secure_renegotiation": None if reneg is None else bool(reneg.get("supports_secure_renegotiation")),
        "client_renegotiation_accepted": None
        if reneg is None
        else bool(reneg.get("is_vulnerable_to_client_renegotiation_dos")),
    }
    for key, field_name, label in (
        ("heartbleed", "is_vulnerable_to_heartbleed", "heartbleed"),
        ("openssl_ccs_injection", "is_vulnerable_to_ccs_injection", "ccs_injection"),
        ("tls_compression", "supports_compression", "compression"),
    ):
        result = _plugin_result(scan_result, key)
        if result is None:
            summary["incomplete_checks"].append(key)
            summary[label] = None
        else:
            summary[label] = bool(result.get(field_name))
    robot = _plugin_result(scan_result, "robot")
    summary["robot"] = None if robot is None else str(robot.get("robot_result") or "")
    return summary


def evaluate_controls(servers: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {
        control_id: {"vulnerable": False, "reasons": [], "observations": [], "complete": True}
        for control_id in TLS_CONTROL_IDS
    }
    for server in servers:
        name = f"{server.get('host')}:{server.get('port')}"
        incomplete = set(server.get("incomplete_checks") or [])
        if "connectivity" in incomplete:
            for item in results.values():
                item["complete"] = False
                item["observations"].append(f"{name} 연결 또는 점검이 완료되지 않았습니다.")
            continue
        if any(key.endswith("_cipher_suites") for key in incomplete):
            results["EFI-MA-41"]["complete"] = False
            results["EFI-MA-42"]["complete"] = False
        for protocol in server.get("weak_protocols") or []:
            results["EFI-MA-41"]["vulnerable"] = True
            results["EFI-MA-41"]["reasons"].append(f"{name} {protocol} 허용")
        for cipher in server.get("insecure_ciphers") or []:
            results["EFI-MA-42"]["vulnerable"] = True
            results["EFI-MA-42"]["reasons"].append(f"{name} INSECURE 암호 {cipher}")
        for cipher in (server.get("weak_ciphers") or [])[:20]:
            results["EFI-MA-42"]["observations"].append(f"{name} WEAK 암호(문서상 양호) {cipher}")
        component = results["EFI-MA-43"]
        for label, flag, reason in (
            ("heartbleed", server.get("heartbleed"), "Heartbleed(CVE-2014-0160)"),
            ("ccs_injection", server.get("ccs_injection"), "CCS Injection(CVE-2014-0224)"),
        ):
            if flag is None:
                component["complete"] = False
            elif flag:
                component["vulnerable"] = True
                component["reasons"].append(f"{name} {reason} 취약")
        if (server.get("protocols") or {}).get("SSL 3.0"):
            component["vulnerable"] = True
            component["reasons"].append(f"{name} SSLv3 허용(POODLE, CVE-2014-3566)")
        if server.get("export_rsa_ciphers"):
            component["vulnerable"] = True
            component["reasons"].append(f"{name} EXPORT RSA 암호 허용(FREAK, CVE-2015-0204)")
        robot = server.get("robot") or ""
        if robot.startswith("VULNERABLE"):
            component["observations"].append(f"{name} ROBOT {robot}")
        if server.get("compression"):
            component["observations"].append(f"{name} TLS 압축 지원(CRIME 관찰)")
        reneg = server.get("renegotiation") or {}
        secure = reneg.get("supports_secure_renegotiation")
        client = reneg.get("client_renegotiation_accepted")
        if secure is None or client is None:
            results["EFI-MA-44"]["complete"] = False
        elif client and not secure:
            results["EFI-MA-44"]["vulnerable"] = True
            results["EFI-MA-44"]["reasons"].append(
                f"{name} 안전하지 않은 클라이언트 재협상 허용(CVE-2009-3555)"
            )
        elif client:
            results["EFI-MA-44"]["observations"].append(
                f"{name} 안전한 재협상 환경에서 클라이언트 재협상 허용(DoS 관찰)"
            )
    results[TLS_ANY_KEY] = {
        "vulnerable": any(results[item]["vulnerable"] for item in TLS_CONTROL_IDS),
        "reasons": [reason for item in TLS_CONTROL_IDS for reason in results[item]["reasons"]],
        "observations": [],
        "complete": all(results[item]["complete"] for item in TLS_CONTROL_IDS),
    }
    return results


def parse_sslyze_payload(payload: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    servers = [
        summarize_server(item)
        for item in payload.get("server_scan_results") or []
        if isinstance(item, dict)
    ]
    invalid = payload.get("invalid_server_strings") or []
    if invalid:
        servers.extend(
            {
                "host": str(item.get("server_string") if isinstance(item, dict) else item),
                "port": None,
                "incomplete_checks": ["connectivity"],
            }
            for item in invalid
        )
    return servers, evaluate_controls(servers)


def synthetic_payload(targets: list[TlsTarget]) -> dict[str, Any]:
    """Deterministic SYNTHETIC result for Mock projects (TLS 1.0 still enabled)."""

    def suites(names: list[str]) -> dict[str, Any]:
        return {
            "status": "COMPLETED",
            "result": {
                "accepted_cipher_suites": [
                    {"cipher_suite": {"name": name}} for name in names
                ],
                "rejected_cipher_suites": [],
            },
        }

    return {
        "sslyze_version": "synthetic",
        "invalid_server_strings": [],
        "server_scan_results": [
            {
                "server_location": {"hostname": target.host, "port": target.port, "ip_address": "192.0.2.10"},
                "connectivity_status": "COMPLETED",
                "scan_status": "COMPLETED",
                "scan_result": {
                    "ssl_2_0_cipher_suites": suites([]),
                    "ssl_3_0_cipher_suites": suites([]),
                    "tls_1_0_cipher_suites": suites(["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"]),
                    "tls_1_1_cipher_suites": suites([]),
                    "tls_1_2_cipher_suites": suites(
                        ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"]
                    ),
                    "tls_1_3_cipher_suites": suites(["TLS_AES_128_GCM_SHA256"]),
                    "session_renegotiation": {
                        "status": "COMPLETED",
                        "result": {
                            "supports_secure_renegotiation": True,
                            "is_vulnerable_to_client_renegotiation_dos": False,
                        },
                    },
                    "heartbleed": {"status": "COMPLETED", "result": {"is_vulnerable_to_heartbleed": False}},
                    "openssl_ccs_injection": {"status": "COMPLETED", "result": {"is_vulnerable_to_ccs_injection": False}},
                    "tls_compression": {"status": "COMPLETED", "result": {"supports_compression": False}},
                    "robot": {"status": "COMPLETED", "result": {"robot_result": "NOT_VULNERABLE_NO_ORACLE"}},
                },
            }
            for target in targets
        ],
    }


class TlsScanAdapter:
    name = "sslyze"

    def __init__(self, settings: AppSettings):
        self.settings = settings

    async def health(self) -> dict[str, Any]:
        binary = self.settings.resolved_tool("sslyze")
        if not binary:
            return {
                "name": self.name,
                "status": CapabilityStatus.NOT_CONFIGURED.value,
                "message": "sslyze 실행 파일을 찾을 수 없습니다. install_oss_tools.ps1 -SSLyze -AcceptCopyleftLicenses 또는 경로 설정이 필요합니다.",
                "license": "AGPL-3.0 (subprocess boundary)",
            }
        result = await run_command([binary, "--help"], timeout=20)
        version = None
        match = re.search(r"SSLyze version ([0-9.]+)", result.stdout + result.stderr)
        if match:
            version = match.group(1)
        return {
            "name": self.name,
            "status": CapabilityStatus.AVAILABLE.value if version else CapabilityStatus.FAILED.value,
            "version": version,
            "path": binary,
            "message": "TLS 구성 점검을 사용할 수 있습니다." if version else (result.error or "sslyze 버전을 확인하지 못했습니다."),
            "license": "AGPL-3.0 (subprocess boundary)",
        }

    async def scan(
        self,
        targets: list[TlsTarget],
        *,
        output_dir: Path,
        synthetic: bool = False,
    ) -> TlsScanOutcome:
        output_dir.mkdir(parents=True, exist_ok=True)
        raw_path = output_dir / f"tls-scan-{uuid.uuid4()}.json"
        if synthetic:
            payload = synthetic_payload(targets)
            raw_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            servers, controls = parse_sslyze_payload(payload)
            return TlsScanOutcome(
                CapabilityStatus.AVAILABLE,
                "SYNTHETIC MOCK TLS 구성 점검 결과입니다.",
                command="mock sslyze " + " ".join(item.display for item in targets),
                raw_path=raw_path,
                servers=servers,
                control_results=controls,
                sslyze_version="synthetic",
                synthetic=True,
            )
        binary = self.settings.resolved_tool("sslyze")
        if not binary:
            return TlsScanOutcome(
                CapabilityStatus.NOT_CONFIGURED,
                "sslyze 실행 파일을 찾을 수 없어 TLS 구성 점검을 실행하지 않았습니다.",
            )
        command = [
            binary,
            f"--json_out={raw_path}",
            "--quiet",
            "--sslv2",
            "--sslv3",
            "--tlsv1",
            "--tlsv1_1",
            "--tlsv1_2",
            "--tlsv1_3",
            "--reneg",
            "--heartbleed",
            "--openssl_ccs",
            "--robot",
            "--compression",
            "--mozilla_config=disable",
            *[item.sslyze_target for item in targets],
        ]
        result = await run_command(
            command,
            timeout=SCAN_TIMEOUT_SECONDS,
            memory_limit_mb=self.settings.external_tool_memory_mb,
            cpu_limit_seconds=self.settings.external_tool_cpu_seconds,
        )
        if not raw_path.is_file():
            return TlsScanOutcome(
                CapabilityStatus.FAILED,
                f"sslyze 결과 파일이 생성되지 않았습니다: {result.error or result.stderr.strip()[:300]}",
                command=result.display_command,
            )
        try:
            payload = json.loads(raw_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return TlsScanOutcome(
                CapabilityStatus.FAILED,
                f"sslyze JSON을 해석하지 못했습니다: {exc}",
                command=result.display_command,
                raw_path=raw_path,
            )
        servers, controls = parse_sslyze_payload(payload)
        return TlsScanOutcome(
            CapabilityStatus.AVAILABLE,
            "TLS 구성 점검을 완료했습니다.",
            command=result.display_command,
            raw_path=raw_path,
            servers=servers,
            control_results=controls,
            sslyze_version=str(payload.get("sslyze_version") or "") or None,
        )
