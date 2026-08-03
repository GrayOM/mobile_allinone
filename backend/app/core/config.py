from __future__ import annotations

import os
import shutil
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


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
    data_dir: Path = ROOT_DIR / "data"
    database_url: str = f"sqlite:///{(ROOT_DIR / 'data' / 'workbench.db').as_posix()}"
    frontend_dist: Path = ROOT_DIR / "frontend" / "dist"
    default_mock_mode: bool = True
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
    mobsf_url: str | None = None
    mobsf_api_key: str | None = None
    semgrep_rules_path: Path = ROOT_DIR / "rules" / "semgrep"
    tools: ToolPaths = Field(default_factory=ToolPaths)

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
        "default_mock_mode": _env_bool(
            "MSW_DEFAULT_MOCK_MODE", values.get("default_mock_mode", True)
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
        "mobsf_url": os.getenv("MOBSF_URL", values.get("mobsf_url")),
        "mobsf_api_key": os.getenv("MOBSF_API_KEY"),
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
