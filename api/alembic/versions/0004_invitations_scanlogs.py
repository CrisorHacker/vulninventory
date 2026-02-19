"""invitations and scan logs

Revision ID: 0004_invitations_scanlogs
Revises: 0003_audit_logs
Create Date: 2025-02-13 00:30:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "0004_invitations_scanlogs"
down_revision = "0003_audit_logs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "invitations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False, server_default="member"),
        sa.Column("token", sa.String(length=128), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("accepted_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
    )
    op.create_index("ix_invitations_token", "invitations", ["token"], unique=True)

    op.create_table(
        "scan_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
    )


def downgrade() -> None:
    op.drop_table("scan_logs")
    op.drop_index("ix_invitations_token", table_name="invitations")
    op.drop_table("invitations")
