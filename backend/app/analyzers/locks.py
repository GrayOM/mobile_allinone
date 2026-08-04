from __future__ import annotations

import asyncio


class AnalysisLeaseManager:
    def __init__(self):
        self._active: set[str] = set()
        self._guard = asyncio.Lock()

    async def try_acquire(self, app_id: str) -> bool:
        async with self._guard:
            if app_id in self._active:
                return False
            self._active.add(app_id)
            return True

    async def release(self, app_id: str) -> None:
        async with self._guard:
            self._active.discard(app_id)
