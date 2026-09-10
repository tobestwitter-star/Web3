"""Small DB adapter: SQLite for local/tests, Neon PostgreSQL when DATABASE_URL is set."""
from __future__ import annotations
import os, sqlite3

try:
    import psycopg
except ImportError:
    psycopg = None


def is_postgres() -> bool:
    return bool(os.environ.get("DATABASE_URL"))


def connect(path: str):
    if is_postgres():
        if psycopg is None:
            raise RuntimeError("psycopg is required when DATABASE_URL is configured")
        return psycopg.connect(os.environ["DATABASE_URL"])
    return sqlite3.connect(path)


def sql(statement: str) -> str:
    return statement.replace("?", "%s") if is_postgres() else statement
