"""Frida 16/17 runtime compatibility for approved scripts.

Frida 17 removed the Java/ObjC bridges from GumJS and the static ``Module``
lookup helpers. Built-in and approved scripts are written against the classic
API, so the loader prepares their source before ``Session.create_script``:

* Frida < 17: prepend a no-op-on-16 shim and load the script unchanged.
* Frida >= 17 and the script references ``Java``/``ObjC``: bundle the shim and
  the pinned bridges with ``frida.Compiler``; the untouched script text is
  embedded as a string and run through a global indirect ``eval`` so it keeps
  classic (non-module, non-strict) semantics.
* Frida >= 17 without bridge references: prepend the shim only.

The approved script text and its SHA-256 are never modified. The result
reports the exact wrapper mode and the SHA-256 of the produced source so the
Run evidence shows what was actually injected.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from backend.app.core.config import ROOT_DIR

RUNTIME_DIR = ROOT_DIR / "scripts" / "frida" / "runtime"

LEGACY_MODULE_SHIM = """\
(function () {
  if (typeof Module === 'undefined' || typeof Process === 'undefined') return;
  if (typeof Module.findExportByName !== 'function') {
    Module.findExportByName = function (moduleName, exportName) {
      if (moduleName === null || moduleName === undefined) {
        return Module.findGlobalExportByName(exportName);
      }
      const module = Process.findModuleByName(moduleName);
      return module === null ? null : module.findExportByName(exportName);
    };
  }
  if (typeof Module.getExportByName !== 'function') {
    Module.getExportByName = function (moduleName, exportName) {
      if (moduleName === null || moduleName === undefined) {
        return Module.getGlobalExportByName(exportName);
      }
      return Process.getModuleByName(moduleName).getExportByName(exportName);
    };
  }
  if (typeof Module.findBaseAddress !== 'function') {
    Module.findBaseAddress = function (moduleName) {
      const module = Process.findModuleByName(moduleName);
      return module === null ? null : module.base;
    };
  }
  if (typeof Module.getBaseAddress !== 'function') {
    Module.getBaseAddress = function (moduleName) {
      return Process.getModuleByName(moduleName).base;
    };
  }
})();
"""

_BRIDGES = (
    ("Java", "frida-java-bridge"),
    ("ObjC", "frida-objc-bridge"),
)
_BRIDGE_USE = {
    name: re.compile(rf"(?<![\w$.]){name}\s*\.") for name, _ in _BRIDGES
}
_BUILD_LOCK = threading.Lock()


class FridaRuntimeUnavailable(RuntimeError):
    """The connected Frida needs bridges that are not installed locally."""


@dataclass(frozen=True, slots=True)
class PreparedScript:
    source: str
    mode: str
    frida_version: str | None
    bridges: tuple[str, ...]
    source_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "frida_version": self.frida_version,
            "bridges": list(self.bridges),
            "loaded_source_sha256": self.source_sha256,
        }


def parse_version(value: Any) -> tuple[int, ...] | None:
    match = re.match(r"\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(value or ""))
    if not match:
        return None
    return tuple(int(part) for part in match.groups() if part is not None)


def required_bridges(content: str) -> tuple[str, ...]:
    return tuple(name for name, _ in _BRIDGES if _BRIDGE_USE[name].search(content))


def bridge_status(runtime_dir: Path = RUNTIME_DIR) -> dict[str, Any]:
    installed = {
        package: (runtime_dir / "node_modules" / package / "package.json").is_file()
        for _, package in _BRIDGES
    }
    return {
        "runtime_dir": str(runtime_dir),
        "installed": installed,
        "ready": all(installed.values()),
    }


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _bundle(
    frida_module: Any,
    content: str,
    bridges: tuple[str, ...],
    *,
    runtime_dir: Path,
    cache_dir: Path | None,
    version_text: str,
) -> str:
    status = bridge_status(runtime_dir)
    packages = dict(_BRIDGES)
    missing = [packages[name] for name in bridges if not status["installed"][packages[name]]]
    if missing:
        raise FridaRuntimeUnavailable(
            "Frida 17 이상에서는 "
            + ", ".join(missing)
            + " 런타임 브리지가 필요합니다. install_oss_tools.ps1 -FridaRuntime 또는 "
            "scripts/install_frida_runtime.sh를 실행하세요."
        )
    if not hasattr(frida_module, "Compiler"):
        raise FridaRuntimeUnavailable("현재 Python frida 바인딩에 Compiler API가 없습니다.")
    key = _sha256(
        json.dumps(
            {
                "frida": version_text,
                "bridges": bridges,
                "shim": _sha256(LEGACY_MODULE_SHIM),
                "content": _sha256(content),
            },
            sort_keys=True,
        )
    )
    cached = cache_dir / f"{key}.js" if cache_dir else None
    if cached and cached.is_file():
        return cached.read_text(encoding="utf-8")

    with _BUILD_LOCK:
        build_dir = runtime_dir / ".build" / str(uuid.uuid4())
        build_dir.mkdir(parents=True, exist_ok=False)
        try:
            bridge_lines = []
            for name in bridges:
                bridge_lines.append(f'import {name} from "{packages[name]}";')
            for name in bridges:
                bridge_lines.append(f"globalThis.{name} = {name};")
            (build_dir / "bridges.js").write_text("\n".join(bridge_lines) + "\n", encoding="utf-8")
            (build_dir / "shim.js").write_text(LEGACY_MODULE_SHIM, encoding="utf-8")
            # The approved text is evaluated with an indirect eval in global
            # scope so it keeps classic-script (sloppy, non-module) semantics:
            # implicit globals, top-level `this` and legacy syntax behave as on
            # Frida 16. Importing it as a module would force strict mode.
            (build_dir / "approved.js").write_text(
                "export default " + json.dumps(content + "\n//# sourceURL=approved.js") + ";\n",
                encoding="utf-8",
            )
            (build_dir / "main.js").write_text(
                'import "./bridges.js";\n'
                'import "./shim.js";\n'
                'import approvedSource from "./approved.js";\n'
                "(0, eval)(approvedSource);\n",
                encoding="utf-8",
            )
            compiler = frida_module.Compiler()
            bundle = compiler.build(
                str(build_dir / "main.js"),
                project_root=str(runtime_dir),
                source_maps="omitted",
                compression="none",
                type_check="none",
            )
        finally:
            shutil.rmtree(build_dir, ignore_errors=True)
    if cached:
        cached.parent.mkdir(parents=True, exist_ok=True)
        temporary = cached.with_suffix(f".{uuid.uuid4()}.tmp")
        temporary.write_text(bundle, encoding="utf-8")
        temporary.replace(cached)
    return bundle


def prepare_script_source(
    frida_module: Any,
    content: str,
    *,
    runtime_dir: Path = RUNTIME_DIR,
    cache_dir: Path | None = None,
) -> PreparedScript:
    version_text = str(getattr(frida_module, "__version__", "") or "")
    version = parse_version(version_text)
    bridges = required_bridges(content)
    if version is not None and version[0] >= 17 and bridges:
        source = _bundle(
            frida_module,
            content,
            bridges,
            runtime_dir=runtime_dir,
            cache_dir=cache_dir,
            version_text=version_text,
        )
        mode = "frida17_bridge_bundle"
    else:
        source = LEGACY_MODULE_SHIM + "\n" + content
        mode = "legacy_shim" if version is None or version[0] < 17 else "frida17_shim"
        bridges = ()
    return PreparedScript(
        source=source,
        mode=mode,
        frida_version=version_text or None,
        bridges=bridges,
        source_sha256=_sha256(source),
    )


def prepare_cli_source(content: str, frida_cli_version: str | None) -> str:
    """frida-tools CLI bundles the bridges itself; only the shim is needed."""
    return LEGACY_MODULE_SHIM + "\n" + content
