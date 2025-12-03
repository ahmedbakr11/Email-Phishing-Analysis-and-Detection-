"""reorder user columns

Revision ID: 0daa05157add
Revises: 1e3a296c4ab0
Create Date: 2025-10-14 14:33:23.081238

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0daa05157add'
down_revision = '1e3a296c4ab0'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "user_tmp",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("fullname", sa.String(50), nullable=False),
        sa.Column("username", sa.String(50), nullable=False),
        sa.Column("email", sa.String(120), nullable=False),
        sa.Column("password", sa.String(), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.UniqueConstraint("username"),
        sa.UniqueConstraint("email"),
    )

    conn = op.get_bind()
    conn.execute(
        sa.text(
            "INSERT INTO user_tmp (id, fullname, username, email, password, role) "
            "SELECT id, fullname, username, email, password, role FROM user"
        )
    )

    op.drop_table("user")
    op.rename_table("user_tmp", "user")


def downgrade():
    op.create_table(
        "user_tmp",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(50), nullable=False),
        sa.Column("email", sa.String(120), nullable=False),
        sa.Column("password", sa.String(), nullable=False),
        sa.Column("fullname", sa.String(50), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.UniqueConstraint("username"),
        sa.UniqueConstraint("email"),
    )

    conn = op.get_bind()
    conn.execute(
        sa.text(
            "INSERT INTO user_tmp (id, username, email, password, fullname, role) "
            "SELECT id, username, email, password, fullname, role FROM user"
        )
    )

    op.drop_table("user")
    op.rename_table("user_tmp", "user")
