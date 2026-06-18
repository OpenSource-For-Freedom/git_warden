"""SQLite persistence for the ingestion store."""

from .database import Database, connect, init_db

__all__ = ["Database", "connect", "init_db"]
