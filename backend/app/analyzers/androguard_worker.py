from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: androguard_worker <apk> <output.json>", file=sys.stderr)
        return 2
    artifact_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    try:
        from androguard.core.apk import APK
        from loguru import logger

        from backend.app.analyzers.adapters import AndroguardAnalyzerAdapter

        logger.disable("androguard")
        payload = AndroguardAnalyzerAdapter._inspect(APK, artifact_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(payload, ensure_ascii=False, default=str), encoding="utf-8"
        )
        return 0
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
