"""Merge heads for tool_counter and google_token edits.

Revision ID: f7a5b8c0d9e0
Revises: 5a6a0e0e5c3c, 95c6b281d8c1
Create Date: 2025-12-02 21:50:00.000000
"""
from alembic import op


# revision identifiers, used by Alembic.
revision = "f7a5b8c0d9e0"
down_revision = ("5a6a0e0e5c3c", "95c6b281d8c1")
branch_labels = None
depends_on = None


def upgrade():
    # No-op merge revision to unify heads
    pass


def downgrade():
    # No-op merge revision
    pass
