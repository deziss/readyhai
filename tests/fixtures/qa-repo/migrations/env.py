import os
from alembic import context
from sqlalchemy import create_engine

url = os.environ["DATABASE_URL"]


def run():
    engine = create_engine(url)
    with engine.connect() as conn:
        context.configure(connection=conn, target_metadata=None)
        with context.begin_transaction():
            context.run_migrations()


run()
