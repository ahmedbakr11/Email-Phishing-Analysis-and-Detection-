"""create tool_counter table

Revision ID: b97441d93546
Revises: 111b7d66ed41
Create Date: 2025-10-17 23:55:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = "b97441d93546"
down_revision = "111b7d66ed41"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "tool_counter",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(50), nullable=False),
        sa.Column("tool_name", sa.String(120), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="0"),
    )

    with op.batch_alter_table("tool_counter") as batch_op:
        batch_op.alter_column("count", server_default=None)


def downgrade():
    op.drop_table("tool_counter")
