"""auth and multitenant

Revision ID: 0002_auth_multitenant
Revises: 0001_initial
Create Date: 2025-02-13 00:10:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "0002_auth_multitenant"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "organizations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_organizations_name", "organizations", ["name"], unique=True)

    op.create_table(
        "memberships",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False, server_default="member"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
    )

    op.create_table(
        "projects",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
    )

    op.add_column("assets", sa.Column("project_id", sa.Integer(), nullable=True))
    op.add_column("scans", sa.Column("project_id", sa.Integer(), nullable=True))
    op.create_foreign_key("fk_assets_project", "assets", "projects", ["project_id"], ["id"])
    op.create_foreign_key("fk_scans_project", "scans", "projects", ["project_id"], ["id"])


def downgrade() -> None:
    op.drop_constraint("fk_scans_project", "scans", type_="foreignkey")
    op.drop_constraint("fk_assets_project", "assets", type_="foreignkey")
    op.drop_column("scans", "project_id")
    op.drop_column("assets", "project_id")

    op.drop_table("projects")
    op.drop_table("memberships")
    op.drop_index("ix_organizations_name", table_name="organizations")
    op.drop_table("organizations")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
