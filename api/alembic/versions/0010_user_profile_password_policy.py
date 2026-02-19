"""user profile and password policy

Revision ID: 0010_user_profile
Revises: 0009_templates
Create Date: 2026-02-14 02:10:00
"""

from alembic import op
import sqlalchemy as sa

revision = "0010_user_profile"
down_revision = "0009_templates"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("full_name", sa.String(length=255), nullable=False, server_default=""),
    )
    op.add_column(
        "users",
        sa.Column("phone", sa.String(length=32), nullable=False, server_default=""),
    )
    op.add_column(
        "users",
        sa.Column("title", sa.String(length=128), nullable=False, server_default=""),
    )
    op.add_column(
        "users",
        sa.Column("profile_completed", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "users",
        sa.Column(
            "password_updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "password_updated_at")
    op.drop_column("users", "profile_completed")
    op.drop_column("users", "title")
    op.drop_column("users", "phone")
    op.drop_column("users", "full_name")
