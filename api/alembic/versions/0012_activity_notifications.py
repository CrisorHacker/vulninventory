"""user activities and notification preferences

Revision ID: 0012_activity_notifications
Revises: 0011_password_resets
Create Date: 2026-02-17 03:00:00
"""

from alembic import op
import sqlalchemy as sa

revision = "0012_activity_notifications"
down_revision = "0011_password_resets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user_activities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(length=255), nullable=False),
        sa.Column("ip", sa.String(length=64), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
    )
    op.create_table(
        "notification_preferences",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("critical_vulns", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("assigned_vulns", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("status_updates", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("reports", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("system_alerts", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("channel", sa.String(length=16), nullable=False, server_default="email"),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.UniqueConstraint("user_id"),
    )


def downgrade() -> None:
    op.drop_table("notification_preferences")
    op.drop_table("user_activities")
