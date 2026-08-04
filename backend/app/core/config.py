from __future__ import annotations

import os
import shutil
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, model_validator

from backend.app.core.targets import is_loopback_host, is_valid_host


ROOT_DIR = Path(__file__).resolve().parents[3]


def _load_local_env() -> None:
    path = Path(os.getenv("MSW_ENV_FILE", ROOT_DIR / ".env"))
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_local_env()


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class ToolPaths(BaseModel):
    adb: str = "adb"
    apktool: str = "apktool"
    jadx: str = "jadx"
    aapt: str = "aapt"
    apkanalyzer: str = "apkanalyzer"
    frida: str = "frida"
    frida_ps: str = "frida-ps"
    mitmdump: str = "mitmdump"
    node: str = "node"
    ssh: str = "ssh"
    scp: str = "scp"
    apkid: str = "apkid"
    semgrep: str = "semgrep"
    objection: str = "objection"
    drozer: str = "drozer"
    pymobiledevice3: str = "pymobiledevice3"
    idevice_id: str = "idevice_id"
    ideviceinfo: str = "ideviceinfo"
    ideviceinstaller: str = "ideviceinstaller"
    idevicesyslog: str = "idevicesyslog"
    idevicescreenshot: str = "idevicescreenshot"


class AppSettings(BaseModel):
    app_name: str = "Mobile Security Workbench"
    host: str = "127.0.0.1"
    port: int = 8765
    lan_access: bool = False
    api_token: str | None = None
    admin_token: str | None = None
    trusted_hosts: list[str] = Field(default_factory=list)
    enable_api_docs: bool = False
    data_dir: Path = ROOT_DIR / "data"
    database_url: str = f"sqlite:///{(ROOT_DIR / 'data' / 'workbench.db').as_posix()}"
    frontend_dist: Path = ROOT_DIR / "frontend" / "dist"
    default_mock_mode: bool = False
    auto_open_browser: bool = True
    command_timeout_seconds: int = 30
    max_upload_mb: int = 512
    nvidia_api_key: str | None = None
    nvidia_base_url: str = "https://integrate.api.nvidia.com/v1"
    nvidia_model: str = "meta/llama-3.1-70b-instruct"
    claude_api_key: str | None = None
    claude_base_url: str = "https://api.anthropic.com/v1"
    claude_model: str = "claude-sonnet-4-6"
    ai_min_quality: float = 0.55
    mask_external_ai_data: bool = True
    store_ai_raw_responses: bool = False
    ai_sensitive_keys: list[str] = Field(default_factory=list)
    proxy_listen_host: str = "127.0.0.1"
    archive_max_entries: int = 20_000
    archive_max_uncompressed_mb: int = 1_024
    archive_max_entry_mb: int = 256
    archive_max_entry_ratio: float = 200.0
    archive_max_total_ratio: float = 100.0
    archive_max_nested_count: int = 10
    archive_max_nested_mb: int = 50
    external_tool_memory_mb: int = 2_048
    external_tool_cpu_seconds: int = 300
    mobsf_url: str | None = None
    mobsf_api_key: str | None = None
    mobsf_allowed_networks: list[str] = Field(
        default_factory=lambda: ["127.0.0.0/8", "::1/128"]
    )
    mobsf_allowed_hosts: list[str] = Field(default_factory=list)
    semgrep_rules_path: Path = ROOT_DIR / "rules" / "semgrep"
    tools: ToolPaths = Field(default_factory=ToolPaths)

    @model_validator(mode="after")
    def validate_server_exposure(self):
        host = self.host.strip().strip("[]").rstrip(".")
        if host in {"0.0.0.0", "::", "*"} or not is_valid_host(host):
            raise ValueError("서버는 wildcard가 아닌 특정 loopback 또는 LAN 주소에만 바인딩할 수 있습니다.")
        self.host = host
        if not is_loopback_host(host):
            if not self.lan_access:
                raise ValueError("loopback 외 주소는 MSW_LAN_ACCESS=true로 명시적으로 허용해야 합니다.")
            if len(self.api_token or "") < 32 or len(self.admin_token or "") < 32:
                raise ValueError("LAN 실행에는 32자 이상의 임시 API 토큰과 관리자 토큰이 필요합니다.")
        return self

    @property
    def effective_trusted_hosts(self) -> list[str]:
        values = {"127.0.0.1", "localhost", self.host, *self.trusted_hosts}
        return sorted(value for value in values if value)

    @property
    def uploads_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def ai_raw_dir(self) -> Path:
        return self.data_dir / "ai_raw"

    @property
    def analysis_dir(self) -> Path:
        return self.data_dir / "analysis"

    def ensure_directories(self) -> None:
        for path in (
            self.data_dir,
            self.uploads_dir,
            self.evidence_dir,
            self.reports_dir,
            self.ai_raw_dir,
            self.analysis_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)

    def resolved_tool(self, name: str) -> str | None:
        configured = getattr(self.tools, name)
        candidate = Path(configured)
        if candidate.is_file():
            return str(candidate)
        return shutil.which(configured)


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


@lru_cache
def get_settings() -> AppSettings:
    config_file = Path(os.getenv("MSW_CONFIG", ROOT_DIR / "config.yaml"))
    values: dict[str, Any] = {}
    if config_file.is_file():
        loaded = yaml.safe_load(config_file.read_text(encoding="utf-8")) or {}
        if isinstance(loaded, dict):
            values = loaded

    env_values: dict[str, Any] = {
        "host": os.getenv("MSW_HOST", values.get("host", "127.0.0.1")),
        "port": int(os.getenv("MSW_PORT", values.get("port", 8765))),
        "lan_access": _env_bool("MSW_LAN_ACCESS", values.get("lan_access", False)),
        "api_token": os.getenv("MSW_API_TOKEN"),
        "admin_token": os.getenv("MSW_ADMIN_TOKEN"),
        "trusted_hosts": [
            item.strip()
            for item in os.getenv("MSW_TRUSTED_HOSTS", "").split(",")
            if item.strip()
        ] or values.get("trusted_hosts", []),
        "enable_api_docs": _env_bool(
            "MSW_ENABLE_API_DOCS", values.get("enable_api_docs", False)
        ),
        "default_mock_mode": _env_bool(
            "MSW_DEFAULT_MOCK_MODE", values.get("default_mock_mode", False)
        ),
        "auto_open_browser": _env_bool(
            "MSW_AUTO_OPEN_BROWSER", values.get("auto_open_browser", True)
        ),
        "nvidia_api_key": os.getenv("NVIDIA_API_KEY"),
        "claude_api_key": os.getenv("ANTHROPIC_API_KEY"),
        "mask_external_ai_data": _env_bool(
            "MSW_MASK_EXTERNAL_AI_DATA",
            values.get("mask_external_ai_data", True),
        ),
        "store_ai_raw_responses": _env_bool(
            "MSW_STORE_AI_RAW_RESPONSES",
            values.get("store_ai_raw_responses", False),
        ),
        "proxy_listen_host": os.getenv(
            "MSW_PROXY_LISTEN_HOST", values.get("proxy_listen_host", "127.0.0.1")
        ),
        "mobsf_url": os.getenv("MOBSF_URL", values.get("mobsf_url")),
        "mobsf_api_key": os.getenv("MOBSF_API_KEY"),
        "mobsf_allowed_networks": [
            item.strip()
            for item in os.getenv("MSW_MOBSF_ALLOWED_NETWORKS", "").split(",")
            if item.strip()
        ] or values.get("mobsf_allowed_networks", ["127.0.0.0/8", "::1/128"]),
        "mobsf_allowed_hosts": [
            item.strip().lower()
            for item in os.getenv("MSW_MOBSF_ALLOWED_HOSTS", "").split(",")
            if item.strip()
        ] or values.get("mobsf_allowed_hosts", []),
    }
    if os.getenv("MSW_DATA_DIR"):
        configured_data_dir = Path(os.environ["MSW_DATA_DIR"])
        env_values["data_dir"] = configured_data_dir
        if not os.getenv("MSW_DATABASE_URL"):
            env_values["database_url"] = (
                f"sqlite:///{(configured_data_dir / 'workbench.db').as_posix()}"
            )
    if os.getenv("MSW_DATABASE_URL"):
        env_values["database_url"] = os.environ["MSW_DATABASE_URL"]
    if os.getenv("NVIDIA_MODEL"):
        env_values["nvidia_model"] = os.environ["NVIDIA_MODEL"]
    if os.getenv("ANTHROPIC_MODEL"):
        env_values["claude_model"] = os.environ["ANTHROPIC_MODEL"]
    if os.getenv("MSW_SEMGREP_RULES_PATH"):
        env_values["semgrep_rules_path"] = Path(os.environ["MSW_SEMGREP_RULES_PATH"])
    values = _deep_merge(values, env_values)
    settings = AppSettings.model_validate(values)
    if not settings.semgrep_rules_path.is_absolute():
        settings.semgrep_rules_path = ROOT_DIR / settings.semgrep_rules_path
    settings.ensure_directories()
    return settings
