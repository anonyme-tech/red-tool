"""Shared SQLite runtime for persisted audit reports."""

from .database import C2Database


audit_db = C2Database()
