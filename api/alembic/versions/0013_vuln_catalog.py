"""add vuln catalog

Revision ID: 0013_vuln_catalog
Revises: 0012_activity_notifications
Create Date: 2026-02-18 13:58:00.000000
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0013_vuln_catalog"
down_revision = "0012_activity_notifications"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vuln_catalog",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cve_id", sa.String(length=50), nullable=True, unique=True),
        sa.Column("name", sa.String(length=500), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=20), nullable=True),
        sa.Column("base_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(length=200), nullable=True),
        sa.Column("cwe_id", sa.Integer(), nullable=True),
        sa.Column("cwe_name", sa.String(length=300), nullable=True),
        sa.Column("cpe", sa.Text(), nullable=True),
        sa.Column("references", sa.Text(), nullable=True),
        sa.Column("recommendation", sa.Text(), nullable=True),
        sa.Column("exploit_available", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("published_date", sa.DateTime(), nullable=True),
        sa.Column("modified_date", sa.DateTime(), nullable=True),
        sa.Column("source", sa.String(length=50), nullable=False, server_default="manual"),
        sa.Column("is_template", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("idx_vulncat_cve", "vuln_catalog", ["cve_id"])
    op.create_index("idx_vulncat_name", "vuln_catalog", ["name"])
    op.create_index("idx_vulncat_cwe", "vuln_catalog", ["cwe_id"])
    op.create_index("idx_vulncat_severity", "vuln_catalog", ["severity"])


def downgrade() -> None:
    op.drop_index("idx_vulncat_severity", table_name="vuln_catalog")
    op.drop_index("idx_vulncat_cwe", table_name="vuln_catalog")
    op.drop_index("idx_vulncat_name", table_name="vuln_catalog")
    op.drop_index("idx_vulncat_cve", table_name="vuln_catalog")
    op.drop_table("vuln_catalog")
