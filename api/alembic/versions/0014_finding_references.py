"""add finding recommendation and references

Revision ID: 0014_finding_references
Revises: 0013_vuln_catalog
Create Date: 2026-02-18 14:36:00.000000
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0014_finding_references"
down_revision = "0013_vuln_catalog"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("recommendation", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("references", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "references")
    op.drop_column("findings", "recommendation")
