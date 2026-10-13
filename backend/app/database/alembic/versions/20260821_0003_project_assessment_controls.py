"""Add project-scoped custom (exception) controls and catalog exclusions.

Revision ID: 20260821_0003
Revises: 20260821_0002
"""

from typing import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260821_0003"
down_revision: str | None = "20260821_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "project_assessment_controls",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("profile", sa.String(length=40), nullable=False),
        sa.Column("control_id", sa.String(length=40), nullable=False),
        sa.Column("platform_scope", sa.String(length=16), nullable=False, server_default="any"),
        sa.Column("group", sa.String(length=100), nullable=False, server_default=""),
        sa.Column("title", sa.String(length=300), nullable=False, server_default=""),
        sa.Column("criteria", sa.JSON(), nullable=True),
        sa.Column("automation", sa.String(length=30), nullable=False, server_default="manual"),
        sa.Column("evaluator", sa.String(length=40), nullable=False, server_default="manual"),
        sa.Column("risk", sa.String(length=20), nullable=False, server_default="medium"),
        sa.Column("severity", sa.String(length=20), nullable=False, server_default="medium"),
        sa.Column("finding_categories", sa.JSON(), nullable=True),
        sa.Column("procedure", sa.JSON(), nullable=True),
        sa.Column("reference", sa.Text(), nullable=False, server_default=""),
        sa.Column("reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("recorded_by", sa.String(length=100), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("definition_sha256", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "kind", "control_id", name="uq_project_assessment_control"),
    )
    op.create_index(
        "ix_project_assessment_controls_project_id",
        "project_assessment_controls",
        ["project_id"],
        unique=False,
    )
    op.create_index(
        "ix_project_assessment_controls_kind",
        "project_assessment_controls",
        ["kind"],
        unique=False,
    )
    op.create_index(
        "ix_project_assessment_controls_control_id",
        "project_assessment_controls",
        ["control_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_project_assessment_controls_control_id", table_name="project_assessment_controls")
    op.drop_index("ix_project_assessment_controls_kind", table_name="project_assessment_controls")
    op.drop_index("ix_project_assessment_controls_project_id", table_name="project_assessment_controls")
    op.drop_table("project_assessment_controls")
