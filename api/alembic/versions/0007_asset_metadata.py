"""asset metadata

Revision ID: 0007_asset_metadata
Revises: 0006_invite_disable
Create Date: 2026-02-13 22:55:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "0007_asset_metadata"
down_revision = "0006_invite_disable"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("owner_email", sa.String(length=255), nullable=True))
    op.add_column("assets", sa.Column("environment", sa.String(length=32), nullable=True))
    op.add_column("assets", sa.Column("criticality", sa.String(length=16), nullable=True))
    op.add_column("assets", sa.Column("tags", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("assets", "tags")
    op.drop_column("assets", "criticality")
    op.drop_column("assets", "environment")
    op.drop_column("assets", "owner_email")
