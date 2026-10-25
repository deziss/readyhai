"""init"""
from alembic import op

revision = "001"
down_revision = None


def upgrade():
    op.execute("CREATE TABLE orders (id serial primary key)")


def downgrade():
    raise NotImplementedError("down-migration not written")
