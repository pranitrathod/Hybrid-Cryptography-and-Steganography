import os
import unittest
from unittest.mock import patch

from mysql_connection import DatabaseConfig, MySQLDatabase


class FakeCursor:
    def __init__(self):
        self.executed = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, query):
        self.executed.append(query)

    def fetchone(self):
        return (1,)


class FakeConnection:
    def __init__(self):
        self.closed = False
        self.cursor_instance = FakeCursor()

    def cursor(self):
        return self.cursor_instance

    def close(self):
        self.closed = True


class DatabaseConfigTests(unittest.TestCase):
    def test_loads_environment_values(self):
        environment = {
            "DB_HOST": "mysql.example.internal",
            "DB_PORT": "3307",
            "DB_NAME": "stego_data",
            "DB_USER": "service_user",
            "DB_PASSWORD": "test-password",
            "DB_SSL_DISABLED": "true",
        }
        with patch.dict(os.environ, environment, clear=True):
            config = DatabaseConfig.from_environment()

        self.assertEqual(config.host, "mysql.example.internal")
        self.assertEqual(config.port, 3307)
        self.assertTrue(config.ssl_disabled)

    def test_password_is_required(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "DB_PASSWORD"):
                DatabaseConfig.from_environment()


class MySQLDatabaseTests(unittest.TestCase):
    def test_health_check_runs_query_and_closes_connection(self):
        connection = FakeConnection()
        config = DatabaseConfig("localhost", 3306, "cloud_security", "app", "secret", False)
        database = MySQLDatabase(config)

        with patch.object(database, "connect", return_value=connection):
            self.assertTrue(database.health_check())

        self.assertEqual(connection.cursor_instance.executed, ["SELECT 1"])
        self.assertTrue(connection.closed)


if __name__ == "__main__":
    unittest.main()
