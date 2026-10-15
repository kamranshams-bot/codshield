from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings

IS_SQLITE = settings.DATABASE_URL.startswith("sqlite")
if IS_SQLITE:
    _connect_args = {"check_same_thread": False}
else:
    # A connection that dies silently on the network (no reset) must fail in seconds, not hang a request
    # for the ~15 minutes Linux takes to give up on it. Without these, a few dead sockets exhaust the pool.
    _connect_args = {
        "connect_timeout": 10,          # seconds to open a connection (Neon cold start is ~1-3 s)
        "keepalives": 1, "keepalives_idle": 20, "keepalives_interval": 5, "keepalives_count": 3,
        "tcp_user_timeout": 20000,      # ms: give up on unacknowledged sends (dead peer)
    }
engine = create_engine(settings.DATABASE_URL, connect_args=_connect_args, future=True,
                       pool_pre_ping=True,   # detect connections closed while Neon compute was suspended
                       pool_recycle=240,     # replace idle connections before Neon scale-to-zero (5 min)
                       **({} if IS_SQLITE else {"pool_size": 5, "max_overflow": 10, "pool_timeout": 10}))

if not IS_SQLITE:
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def _session_limits(dbapi_conn, _record):
        """No statement may hold a connection for more than 30 s; abandoned transactions end after 60 s."""
        with dbapi_conn.cursor() as cur:
            cur.execute("SET statement_timeout = '30s'")
            cur.execute("SET idle_in_transaction_session_timeout = '60s'")
        dbapi_conn.commit()


def pool_status() -> dict:
    p = engine.pool
    try:
        return {"size": p.size(), "checked_out": p.checkedout(), "overflow": p.overflow(), "idle": p.checkedin()}
    except Exception:            # SQLite's pool has no size/overflow
        return {}
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
    ("disputes", "verified", "BOOLEAN DEFAULT TRUE"),
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
