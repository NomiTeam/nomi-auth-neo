"""
Run the existing service contract tests against a real Rust subprocess.

Only the test client/application factory are replaced. The reference database
helper is used for fixture SQL and assertions after Rust has initialized schema 5.
"""

from __future__ import annotations

import os
import socket
import sqlite3
import subprocess
import tempfile
import time
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

_harness: Harness | None = None


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("neo-compatibility")
    group.addoption("--neo-binary", type=Path, required=True)
    group.addoption(
        "--neo-reference", "--ref", dest="neo_reference", type=Path, required=True
    )


def pytest_configure(config: pytest.Config) -> None:
    global _harness
    binary = config.getoption("neo_binary").resolve()
    reference = config.getoption("neo_reference").resolve()
    if not binary.is_file():
        raise pytest.UsageError(f"Rust executable does not exist: {binary}")
    if not (reference / "tests/test_service.py").is_file():
        raise pytest.UsageError("Reference must contain tests/test_service.py")
    _harness = Harness(binary, reference)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    assert _harness is not None
    patched = set()
    for item in items:
        if Path(item.path).resolve() != _harness.reference / "tests/test_service.py":
            continue
        module = item.module
        if module not in patched:
            module.create_app = _harness.create_app
            module.TestClient = RustClient
            patched.add(module)
        if (
            item.originalname
            == "test_schema_four_upgrade_keeps_existing_accounts_and_sessions"
        ):
            item.add_marker(
                pytest.mark.skip(
                    reason=(
                        "This reference test directly invokes Python's schema upgrader; "
                        "Rust v4 migration is covered by native storage tests."
                    )
                )
            )
        if item.originalname == "test_one_grant_uses_one_issue_timestamp":
            item.add_marker(
                pytest.mark.skip(
                    reason=(
                        "Monkeypatching Python's clock cannot control the Rust process; "
                        "native grant and persisted-expiry tests cover this contract."
                    )
                )
            )


@pytest.hookimpl(trylast=True)
def pytest_runtest_teardown() -> None:
    if _harness is not None:
        _harness.close()


def pytest_unconfigure() -> None:
    if _harness is not None:
        _harness.close()


class Harness:
    def __init__(self, binary: Path, reference: Path) -> None:
        self.binary = binary
        self.reference = reference
        self.apps: list[RustApp] = []
        self.clients: list[RustClient] = []

    def create_app(self, settings: Any) -> RustApp:
        # Starting the executable here also exercises startup-only failure tests.
        directory = Path(settings.data_dir).resolve()
        for app in self.apps:
            if app.directory == directory:
                app.close()
        app = RustApp(self, settings, directory)
        self.apps.append(app)
        try:
            app.start()
        except BaseException:
            app.close()
            raise
        return app

    def close(self) -> None:
        for client in self.clients:
            client.close()
        for app in reversed(self.apps):
            app.close()
        self.clients.clear()
        self.apps.clear()


class RustApp:
    def __init__(self, harness: Harness, settings: Any, directory: Path) -> None:
        self.harness = harness
        self.settings = settings
        self.directory = directory
        self.process: subprocess.Popen[bytes] | None = None
        self.logs = Path(tempfile.mkdtemp(prefix="nomi-neo-contract-"))
        self.log_path = self.logs / "server.log"
        self._log = self.log_path.open("ab")
        self.environment = service_environment(settings)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.base_url = f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        command = [
            str(self.harness.binary),
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            str(self.port),
        ]
        self.process = subprocess.Popen(
            command,
            cwd=self.logs,
            env=self.environment,
            stdout=self._log,
            stderr=self._log,
        )
        self._wait_ready()
        self._assert_schema()
        from src.storage.database import Database

        # The schema assertion prevents Python initialization from hiding Rust defects.
        witness = DatabaseWitness(self, Database.from_settings(self.settings))
        self.state = SimpleNamespace(settings=self.settings, db=witness)

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + 60
        with httpx.Client(
            base_url=self.base_url, timeout=0.5, trust_env=False
        ) as client:
            while time.monotonic() < deadline:
                assert self.process is not None
                if self.process.poll() is not None:
                    text = self.log_path.read_text(encoding="utf-8", errors="replace")
                    if "RSA" in text:
                        raise TypeError("Rust rejected an invalid RSA signing key")
                    raise RuntimeError(
                        f"Rust startup failed; diagnostic log: {self.log_path}"
                    )
                try:
                    response = client.get("/health")
                    if response.status_code == 200:
                        return
                except httpx.TransportError:
                    pass
                time.sleep(0.05)
        raise TimeoutError(
            f"Rust health check did not become ready; log: {self.log_path}"
        )

    def _assert_schema(self) -> None:
        expected = {
            "schema_versions",
            "accounts",
            "profiles",
            "identities",
            "registrations",
            "receipts",
            "tokens",
            "joins",
            "login_requests",
            "audit",
            "login_retries",
            "refresh_retries",
        }
        if self.settings.database_backend == "sqlite":
            path = self.directory / "nomi-auth.sqlite3"
            with closing(
                sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
            ) as connection:
                tables = {
                    record[0]
                    for record in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                version = connection.execute(
                    "SELECT MAX(version) FROM schema_versions"
                ).fetchone()[0]
                columns = {
                    record[1]
                    for record in connection.execute("PRAGMA table_info(accounts)")
                }
        else:
            import pymysql

            with (
                closing(
                    pymysql.connect(
                        host=self.settings.mysql_host,
                        port=self.settings.mysql_port,
                        user=self.settings.mysql_user,
                        password=self.settings.mysql_password.get_secret_value(),
                        database=self.settings.mysql_database,
                        charset="utf8mb4",
                    )
                ) as connection,
                connection.cursor() as cursor,
            ):
                cursor.execute("SHOW TABLES")
                tables = {record[0] for record in cursor.fetchall()}
                cursor.execute("SELECT MAX(version) FROM schema_versions")
                version = cursor.fetchone()[0]
                cursor.execute("SHOW COLUMNS FROM accounts")
                columns = {record[0] for record in cursor.fetchall()}
        if not expected <= tables or version != 5 or "password_hash" in columns:
            raise AssertionError(
                "Rust did not produce a complete passwordless schema 5 before SQL assertions"
            )

    def command(self, *arguments: str) -> None:
        result = subprocess.run(
            [str(self.harness.binary), *arguments],
            cwd=self.logs,
            env=self.environment,
            stdout=self._log,
            stderr=self._log,
            check=False,
            timeout=30,
        )
        if result.returncode:
            raise RuntimeError(
                f"Rust maintenance failed; diagnostic log: {self.log_path}"
            )

    def close(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        if not self._log.closed:
            self._log.close()


class DatabaseWitness:
    def __init__(self, app: RustApp, database: Any) -> None:
        self.app = app
        self.database = database

    def __getattr__(self, name: str) -> Any:
        return getattr(self.database, name)

    def cleanup(self, timestamp: int) -> None:
        # Reference tests use current time and expired fixture rows. Execute Rust cleanup.
        if abs(timestamp - int(time.time())) > 5:
            raise AssertionError(
                "The compatibility adapter cannot change the Rust clock"
            )
        self.app.command("cleanup")


class RustClient(httpx.Client):
    def __init__(self, app: RustApp) -> None:
        self.app = app
        super().__init__(
            base_url=app.base_url, timeout=20, trust_env=False, follow_redirects=True
        )
        app.harness.clients.append(self)


def service_environment(settings: Any) -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("NOMI_")
    }
    for name, value in settings.model_dump().items():
        if value is None:
            continue
        if hasattr(value, "get_secret_value"):
            value = value.get_secret_value()
        if name == "data_dir":
            value = Path(value).resolve()
        environment["NOMI_" + name.upper()] = str(value)
    if os.name == "nt":
        workspace = Path(__file__).resolve().parents[3]
        mingw = workspace / ".tools/mingw/mingw64/bin"
        environment["PATH"] = str(mingw) + os.pathsep + environment.get("PATH", "")
    environment["RUST_LOG"] = "warn"
    return environment
