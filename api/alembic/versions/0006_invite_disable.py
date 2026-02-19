"""invite disable

Revision ID: 0006_invite_disable
Revises: 0005_auth_attempts
Create Date: 2025-02-13 00:50:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "0006_invite_disable"
down_revision = "0005_auth_attempts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("invitations", sa.Column("disabled", sa.Integer(), nullable=False, server_default="0"))


def downgrade() -> None:
    op.drop_column("invitations", "disabled")
