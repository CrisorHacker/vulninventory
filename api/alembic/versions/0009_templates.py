"""finding templates

Revision ID: 0009_templates
Revises: 0008_finding_assign
Create Date: 2026-02-14 01:06:00
"""

from alembic import op
import sqlalchemy as sa

revision = "0009_templates"
down_revision = "0008_finding_assign"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "finding_templates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), nullable=True),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("cwe", sa.String(length=64), nullable=False),
        sa.Column("owasp", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"]),
    )


def downgrade() -> None:
    op.drop_table("finding_templates")
