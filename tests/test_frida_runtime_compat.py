from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.app.frida.runtime_compat import (
    LEGACY_MODULE_SHIM,
    FridaRuntimeUnavailable,
    prepare_cli_source,
    prepare_script_source,
    required_bridges,
)


class _FakeCompiler:
    calls: list[dict] = []

    def build(self, entrypoint: str, **kwargs) -> str:
        build_dir = Path(entrypoint).parent
        files = {path.name: path.read_text(encoding="utf-8") for path in build_dir.iterdir()}
        self.calls.append({"entrypoint": entrypoint, "kwargs": kwargs, "files": files})
        return "/* bundled */" + json.dumps(sorted(files))


class _Frida16:
    __version__ = "16.5.9"


class _Frida17:
    __version__ = "17.23.3"
    Compiler = _FakeCompiler


def _runtime(tmp_path: Path, *packages: str) -> Path:
    root = tmp_path / "runtime"
    for package in packages:
        target = root / "node_modules" / package
        target.mkdir(parents=True)
        (target / "package.json").write_text("{}", encoding="utf-8")
    root.mkdir(exist_ok=True)
    return root


def test_bridge_detection_ignores_typeof_and_property_names():
    assert required_bridges("Java.perform(() => {})") == ("Java",)
    assert required_bridges("if (ObjC.available) {}") == ("ObjC",)
    assert required_bridges("send(typeof Java); obj.Java.x;") == ()


def test_frida16_and_bridge_free_scripts_only_get_the_shim(tmp_path):
    content = "'use strict'; Java.perform(() => send('ok'));"
    legacy = prepare_script_source(_Frida16, content, runtime_dir=_runtime(tmp_path))
    assert legacy.mode == "legacy_shim"
    assert legacy.source.startswith(LEGACY_MODULE_SHIM)
    assert legacy.source.endswith(content)
    native = prepare_script_source(
        _Frida17, "Module.findExportByName(null, 'open');", runtime_dir=_runtime(tmp_path)
    )
    assert native.mode == "frida17_shim"
    assert native.bridges == ()
    assert prepare_cli_source(content, None).endswith(content)


def test_frida17_requires_installed_bridges(tmp_path):
    with pytest.raises(FridaRuntimeUnavailable) as missing:
        prepare_script_source(
            _Frida17, "ObjC.classes.NSString;", runtime_dir=_runtime(tmp_path, "frida-java-bridge")
        )
    assert "frida-objc-bridge" in str(missing.value)


def test_frida17_bundles_approved_text_unchanged_and_caches(tmp_path):
    _FakeCompiler.calls.clear()
    runtime = _runtime(tmp_path, "frida-java-bridge", "frida-objc-bridge")
    content = "'use strict';\nJava.perform(function () { send('approved'); });\n"
    cache = tmp_path / "cache"
    first = prepare_script_source(_Frida17, content, runtime_dir=runtime, cache_dir=cache)
    second = prepare_script_source(_Frida17, content, runtime_dir=runtime, cache_dir=cache)
    assert first.mode == "frida17_bridge_bundle"
    assert first.bridges == ("Java",)
    assert first.source == second.source
    assert len(_FakeCompiler.calls) == 1
    call = _FakeCompiler.calls[0]
    embedded = call["files"]["approved.js"]
    assert embedded.startswith("export default ")
    assert json.loads(embedded[len("export default "):].rstrip().rstrip(";")).startswith(content)
    assert 'import Java from "frida-java-bridge";' in call["files"]["bridges.js"]
    assert "frida-objc-bridge" not in call["files"]["bridges.js"]
    assert call["files"]["main.js"].splitlines() == [
        'import "./bridges.js";',
        'import "./shim.js";',
        'import approvedSource from "./approved.js";',
        "(0, eval)(approvedSource);",
    ]
    assert call["kwargs"]["project_root"] == str(runtime)
    assert not any((runtime / ".build").iterdir())


def test_frida_runtime_status_endpoint(client):
    response = client.get("/api/frida/runtime")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] in {"available", "not_configured"}
    assert "bridges" in body
