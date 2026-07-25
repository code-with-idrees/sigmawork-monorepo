"""
SigmaWork — SQLAlchemy database engine and session factory.
Uses synchronous pyodbc driver for SQL Server (most reliable on Windows).
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import settings

# Create synchronous engine for SQL Server via pyodbc
engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.APP_ENV == "development",
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

# Session factory — each request gets its own session
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""
    pass


def create_tables():
    """Create all tables (used during development startup)."""
    Base.metadata.create_all(bind=engine)
