from alembic import op
import sqlalchemy as sa


revision = "9492846d844c"
down_revision = "b97441d93546"
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    columns = {col["name"] for col in inspector.get_columns("tool_counter")}

    if "user_id" not in columns:
        with op.batch_alter_table("tool_counter") as batch_op:
            batch_op.add_column(sa.Column("user_id", sa.Integer(), nullable=True))

    conn.execute(
        sa.text(
            """
            UPDATE tool_counter
            SET user_id = (
                SELECT id FROM "user" u WHERE u.username = tool_counter.username
            )
            """
        )
    )

    conn.execute(
        sa.text(
            """
            DELETE FROM tool_counter
            WHERE user_id IS NULL
            """
        )
    )

    inspector = sa.inspect(conn)
    fk_names = {
        fk["name"]
        for fk in inspector.get_foreign_keys("tool_counter")
        if fk.get("name")
    }
    unique_names = {
        uc["name"] for uc in inspector.get_unique_constraints("tool_counter")
    }

    with op.batch_alter_table("tool_counter") as batch_op:
        batch_op.alter_column("user_id", existing_type=sa.Integer(), nullable=False)
        if "fk_tool_counter_user_id" not in fk_names:
            batch_op.create_foreign_key(
                "fk_tool_counter_user_id",
                "user",
                ["user_id"],
                ["id"],
                ondelete="CASCADE",
            )
        if "uq_tool_counter_user_tool" not in unique_names:
            batch_op.create_unique_constraint(
                "uq_tool_counter_user_tool", ["user_id", "tool_name"]
            )


def downgrade():
    with op.batch_alter_table("tool_counter") as batch_op:
        batch_op.drop_constraint("uq_tool_counter_user_tool", type_="unique")
        batch_op.drop_constraint("fk_tool_counter_user_id", type_="foreignkey")
        batch_op.drop_column("user_id")
