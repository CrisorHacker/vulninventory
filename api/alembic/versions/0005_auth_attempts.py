"""auth attempts

Revision ID: 0005_auth_attempts
Revises: 0004_invitations_scanlogs
Create Date: 2025-02-13 00:40:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "0005_auth_attempts"
down_revision = "0004_invitations_scanlogs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "auth_attempts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("ip", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("success", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("auth_attempts")
