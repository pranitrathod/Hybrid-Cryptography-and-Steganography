"""Small, reusable MySQL connection helper for the cloud-data service.

Credentials are read from environment variables so they are never committed to source
control. Install ``mysql-connector-python`` before calling :meth:`connect`.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Generator, Protocol


class Connection(Protocol):
    """Minimum interface returned by a MySQL connector."""

    def close(self) -> None:
        """Release the database connection."""

    def cursor(self):  # type: ignore[no-untyped-def]
        """Create a database cursor."""


@dataclass(frozen=True)
class DatabaseConfig:
    """Database configuration sourced from deployment environment variables."""

    host: str
    port: int
    database: str
    user: str
    password: str
    ssl_disabled: bool

    @classmethod
    def from_environment(cls) -> "DatabaseConfig":
        """Build a configuration without exposing credentials in code or logs."""
        password = os.getenv("DB_PASSWORD")
        if not password:
            raise ValueError("DB_PASSWORD must be set.")

        try:
            port = int(os.getenv("DB_PORT", "3306"))
        except ValueError as error:
            raise ValueError("DB_PORT must be an integer.") from error

        return cls(
            host=os.getenv("DB_HOST", "127.0.0.1"),
            port=port,
            database=os.getenv("DB_NAME", "cloud_security"),
            user=os.getenv("DB_USER", "cloud_app"),
            password=password,
            # TLS remains enabled by default; set to true only for local development.
            ssl_disabled=os.getenv("DB_SSL_DISABLED", "false").lower() == "true",
        )


class MySQLDatabase:
    """Creates short-lived MySQL connections and provides a safe health check."""

    def __init__(self, config: DatabaseConfig) -> None:
        self.config = config

    @staticmethod
    def _connector():
        try:
            import mysql.connector
        except ImportError as error:
            raise RuntimeError(
                "mysql-connector-python is required. Run: pip install -r requirements.txt"
            ) from error
        return mysql.connector

    def connect(self) -> Connection:
        """Open a connection using parameterized driver configuration."""
        return self._connector().connect(
            host=self.config.host,
            port=self.config.port,
            database=self.config.database,
            user=self.config.user,
            password=self.config.password,
            ssl_disabled=self.config.ssl_disabled,
            connection_timeout=10,
        )

    @contextmanager
    def session(self) -> Generator[Connection, None, None]:
        """Yield a connection and always close it, including when work fails."""
        connection = self.connect()
        try:
            yield connection
        finally:
            connection.close()

    def health_check(self) -> bool:
        """Return whether the service can execute a minimal query."""
        try:
            with self.session() as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    return cursor.fetchone()[0] == 1
        except Exception:
            return False


if __name__ == "__main__":
    database = MySQLDatabase(DatabaseConfig.from_environment())
    print("MySQL connection is healthy." if database.health_check() else "MySQL is unavailable.")
