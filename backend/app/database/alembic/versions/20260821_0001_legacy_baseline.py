"""Mark the legacy schema through explicit SQLite migration V7.

Revision ID: 20260821_0001
Revises:
"""

from typing import Sequence


revision: str = "20260821_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # The application creates or upgrades the legacy V1-V7 tables before this
    # transitional baseline is stamped. V8+ changes are owned by Alembic.
    return


def downgrade() -> None:
    return
