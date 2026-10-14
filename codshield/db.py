from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings

_connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(settings.DATABASE_URL, connect_args=_connect_args, future=True,
                       pool_pre_ping=True,   # detect connections closed while Neon compute was suspended
                       pool_recycle=240)     # replace idle connections before Neon scale-to-zero (5 min)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def init_db() -> None:
    from . import models  # noqa: F401  (register tables)
    Base.metadata.create_all(engine)
    _add_missing_columns()


# Columns added after the first release. create_all() never alters existing tables,
# so add them here. Only additive, nullable-or-defaulted changes belong in this list.
_NEW_COLUMNS = [
    ("merchants", "plan", "VARCHAR(20) DEFAULT 'free'"),
    ("merchants", "require_approval", "BOOLEAN DEFAULT TRUE"),
    ("merchants", "tier", "VARCHAR(20) DEFAULT 'contributor'"),
]


def _add_missing_columns() -> None:
    from sqlalchemy import inspect, text
    insp = inspect(engine)
    with engine.begin() as c:
        for table, col, ddl in _NEW_COLUMNS:
            if table in insp.get_table_names() and col not in {x["name"] for x in insp.get_columns(table)}:
                c.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}"))


def get_session():
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()
