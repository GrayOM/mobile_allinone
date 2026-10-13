"""Generate the local (never committed) domestic advisory guidance JSON.

Usage:
    python scripts/extract_korean_guidance.py --cii "<주요정보통신기반시설>.docx" --efi "<전자금융기반시설>.docx"
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.app.catalog.guidance import GUIDANCE_PATH  # noqa: E402
from backend.app.catalog.guidance_extract import (  # noqa: E402
    build_guidance,
    verify_against_catalog,
    write_guidance,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cii", required=True, type=Path, help="주요정보통신기반시설 권고안 DOCX")
    parser.add_argument("--efi", required=True, type=Path, help="전자금융기반시설 권고안 DOCX")
    parser.add_argument("--output", type=Path, default=GUIDANCE_PATH)
    args = parser.parse_args()
    payload = build_guidance(args.cii, args.efi)
    problems = verify_against_catalog(payload)
    if problems:
        print("카탈로그와 일치하지 않아 저장하지 않았습니다:", file=sys.stderr)
        for line in problems:
            print(f"  - {line}", file=sys.stderr)
        return 1
    output = write_guidance(payload, args.output)
    print(f"{len(payload['controls'])}개 항목 지침을 저장했습니다: {output}")
    print("이 파일은 고객 권고안 원문을 담고 있으므로 Git에 커밋하지 마세요.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
