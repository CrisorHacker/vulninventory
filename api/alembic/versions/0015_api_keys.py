"""create api_keys table

Revision ID: 0015_api_keys
Revises: 0014_finding_references
Create Date: 2026-02-18 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "0015_api_keys"
down_revision = "0014_finding_references"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("key_hash", sa.String(length=128), nullable=False, unique=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=True),
        sa.Column("project_ids", sa.Text(), nullable=True),
        sa.Column("roles", sa.Text(), nullable=False, server_default='["viewer"]'),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
    )
    op.create_index("idx_api_keys_hash", "api_keys", ["key_hash"], unique=True)


def downgrade() -> None:
    op.drop_index("idx_api_keys_hash", table_name="api_keys")
    op.drop_table("api_keys")
