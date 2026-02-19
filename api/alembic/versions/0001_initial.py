"""initial schema

Revision ID: 0001_initial
Revises: 
Create Date: 2025-02-13 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("uri", sa.String(length=1024), nullable=False),
        sa.Column("type", sa.String(length=64), nullable=False, server_default="api"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_assets_uri", "assets", ["uri"], unique=True)

    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tool", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="queued"),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("scan_metadata", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    )

    op.create_table(
        "raw_reports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tool", sa.String(length=64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("ingested_at", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("rule_id", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False, server_default="info"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="open"),
        sa.Column("cwe", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("owasp", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("raw", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"]),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
    )


def downgrade() -> None:
    op.drop_table("findings")
    op.drop_table("raw_reports")
    op.drop_table("scans")
    op.drop_index("ix_assets_uri", table_name="assets")
    op.drop_table("assets")
