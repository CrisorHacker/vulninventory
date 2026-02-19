"""finding assignments and comments

Revision ID: 0008_finding_assign
Revises: 0007_asset_metadata
Create Date: 2026-02-14 00:41:00
"""

from alembic import op
import sqlalchemy as sa

revision = "0008_finding_assign"
down_revision = "0007_asset_metadata"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("assignee_user_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        "fk_findings_assignee_user_id",
        "findings",
        "users",
        ["assignee_user_id"],
        ["id"],
    )
    op.create_table(
        "finding_comments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
    )


def downgrade() -> None:
    op.drop_table("finding_comments")
    op.drop_constraint("fk_findings_assignee_user_id", "findings", type_="foreignkey")
    op.drop_column("findings", "assignee_user_id")
