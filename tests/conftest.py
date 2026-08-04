from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest


TEST_DATA_DIR = Path(tempfile.mkdtemp(prefix="msw-tests-"))
os.environ["MSW_DATA_DIR"] = str(TEST_DATA_DIR)
os.environ["MSW_AUTO_OPEN_BROWSER"] = "false"

from fastapi.testclient import TestClient  # noqa: E402

from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def client():
    with TestClient(create_app(), base_url="http://127.0.0.1") as test_client:
        yield test_client
