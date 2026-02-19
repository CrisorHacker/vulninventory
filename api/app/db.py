import os

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


class Base(DeclarativeBase):
    pass


def _build_engine_url() -> str:
    return os.environ.get("DATABASE_URL", "sqlite:///./vuln_inventory.db")


def _is_sqlite(url: str) -> bool:
    return url.startswith("sqlite")


DATABASE_URL = _build_engine_url()
connect_args = {"check_same_thread": False} if _is_sqlite(DATABASE_URL) else {}
engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
