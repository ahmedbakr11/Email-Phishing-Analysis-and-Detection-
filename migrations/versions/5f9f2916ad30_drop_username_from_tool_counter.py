from alembic import op
import sqlalchemy as sa


revision = "5f9f2916ad30"
down_revision = "9492846d844c"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "tool_counter_tmp",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("tool_name", sa.String(120), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"], ["user.id"], name="fk_tool_counter_user_id", ondelete="CASCADE"
        ),
        sa.UniqueConstraint("user_id", "tool_name", name="uq_tool_counter_user_tool"),
    )

    op.execute(
        sa.text(
            """
            INSERT INTO tool_counter_tmp (id, user_id, tool_name, count)
            SELECT id, user_id, tool_name, count
            FROM tool_counter
            """
        )
    )

    op.drop_table("tool_counter")
    op.rename_table("tool_counter_tmp", "tool_counter")


def downgrade():
    op.create_table(
        "tool_counter_tmp",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(50), nullable=False),
        sa.Column("tool_name", sa.String(120), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
    )

    op.execute(
        sa.text(
            """
            INSERT INTO tool_counter_tmp (id, username, tool_name, count)
            SELECT tc.id, u.username, tc.tool_name, tc.count
            FROM tool_counter tc
            JOIN "user" u ON u.id = tc.user_id
            """
        )
    )

    op.drop_table("tool_counter")
    op.rename_table("tool_counter_tmp", "tool_counter")
