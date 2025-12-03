"""Replace legacy tool_counter table with Tool_Counter per-user counters.

Revision ID: 5a6a0e0e5c3c
Revises: 5f9f2916ad30
Create Date: 2025-11-25 17:10:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = "5a6a0e0e5c3c"
down_revision = "5f9f2916ad30"
branch_labels = None
depends_on = None


def upgrade():
    op.drop_table("tool_counter")

    op.create_table(
        "Tool_Counter",
        sa.Column("id", sa.Integer(), sa.ForeignKey("user.id"), primary_key=True),
        sa.Column("username", sa.String(length=50), sa.ForeignKey("user.username"), nullable=False),
        sa.Column("Phishing_Email", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("Link_Analyzer", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("Download_Checker", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("Credential_Exposure", sa.Integer(), nullable=False, server_default="0"),
    )

    with op.batch_alter_table("Tool_Counter") as batch_op:
        batch_op.alter_column("Phishing_Email", server_default=None)
        batch_op.alter_column("Link_Analyzer", server_default=None)
        batch_op.alter_column("Download_Checker", server_default=None)
        batch_op.alter_column("Credential_Exposure", server_default=None)


def downgrade():
    op.drop_table("Tool_Counter")

    op.create_table(
        "tool_counter",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("tool_name", sa.String(120), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"], ["user.id"], name="fk_tool_counter_user_id", ondelete="CASCADE"
        ),
        sa.UniqueConstraint("user_id", "tool_name", name="uq_tool_counter_user_tool"),
    )
