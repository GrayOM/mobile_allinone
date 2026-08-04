from __future__ import annotations

import json
from pathlib import Path

from backend.app.ai.masking import mask_context, mask_text
from backend.app.core.config import AppSettings


def save_ai_raw_response(
    settings: AppSettings, filename: str, raw_response: str | None
) -> Path | None:
    if not settings.store_ai_raw_responses or not raw_response:
        return None
    safe_name = Path(filename).name
    try:
        parsed = json.loads(raw_response)
    except (json.JSONDecodeError, TypeError):
        masked, _ = mask_text(raw_response)
    else:
        structured = parsed if isinstance(parsed, dict) else {"response": parsed}
        masked, _ = mask_context(structured, settings.ai_sensitive_keys)
    path = settings.ai_raw_dir / safe_name
    path.write_text(masked, encoding="utf-8")
    return path
