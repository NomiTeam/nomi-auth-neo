"""
Exercise Python/Rust database, backup and credential interoperability.

Run with the Python reference project's development environment. All accounts,
keys, databases and servers belong to a temporary directory; no real bot is used.
"""

import argparse
import base64
import importlib
import io
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from contextlib import closing, contextmanager
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi.testclient import TestClient
from PIL import Image


class PythonReference:
    """
    Load the existing application without inheriting its real dotenv configuration.
    """

    def __init__(self, directory: Path):
        sys.path.insert(0, str(directory))
        application = importlib.import_module("src.app")
        expected = directory / "src" / "app.py"
        if Path(application.__file__).resolve() != expected.resolve():
            raise RuntimeError("The Python reference resolved to a different project")
        self.create_app = application.create_app
        self.settings_type = importlib.import_module("src.core.config").Settings
        maintenance = importlib.import_module("src.storage.maintenance")
        self.backup_data = maintenance.backup_data
        self.restore_data = maintenance.restore_data
        self.tables = importlib.import_module("src.storage.transfer").TABLES

    def settings(self, data_dir: Path):
        return self.settings_type(
            _env_file=None,
            data_dir=data_dir,
            database_backend="sqlite",
            public_url="http://auth.test",
            bot_token="x" * 32,
            bot_app_id="app",
            group_openid="group",
            rename_cooldown=0,
        )

    @contextmanager
    def client(self, data_dir: Path):
        application = self.create_app(self.settings(data_dir))
        with TestClient(application) as client:
            yield client


class Fixture:
    def __init__(self, root: Path):
        self.data_dir = root / "python-data"
        self.archive = root / "python-backup.tar.gz"
        self.session = None
        self.login_request = None
        self.login_retry = None
        self.refresh_seed = None
        self.refresh_retry = None
        self.verification = None
        self.registration = None
        self.registered = None
        self.profile = None
        self.public_key = None
        self.skin_hash = None
        self.skin_bytes = None


def json_response(response, expected=200):
    if response.status_code != expected:
        raise AssertionError(
            f"{response.request.method} {response.request.url.path}: "
            f"expected {expected}, got {response.status_code}"
        )
    return response.json()


def bot_headers():
    return {"Authorization": "Bearer " + "x" * 32}


def bearer(token):
    return {"Authorization": "Bearer " + token}


def event(event_id, **argument):
    return {
        **argument,
        "bot_app_id": "app",
        "group_openid": "group",
        "member_openid": "member",
        "event_id": event_id,
    }


def start_login(client, event_id, request_id):
    request = json_response(client.post("/api/v1/logins", json={}), 201)
    verification = event(event_id, code=request["code"])
    result = json_response(
        client.post(
            "/internal/v1/logins/verify", headers=bot_headers(), json=verification
        )
    )
    if result["status"] != "VERIFIED":
        raise AssertionError("An existing Python account did not resolve by member")
    headers = {**bearer(request["poll_token"]), "X-Request-ID": request_id}
    session = json_response(
        client.post(f"/api/v1/logins/{request['request_id']}/session", headers=headers)
    )
    return request, verification, session


def create_fixture(reference, root):
    fixture = Fixture(root)
    with reference.client(fixture.data_dir) as client:
        request = json_response(client.post("/api/v1/logins", json={}), 201)
        fixture.verification = event("认领-事件", code=request["code"])
        claimed = json_response(
            client.post(
                "/internal/v1/logins/verify",
                headers=bot_headers(),
                json=fixture.verification,
            )
        )
        if claimed != {"status": "AWAITING_NAME"}:
            raise AssertionError("The Python registration was not claimed")
        fixture.registration = event("注册-事件", name="Alice")
        fixture.registered = json_response(
            client.post(
                "/internal/v1/logins/register",
                headers=bot_headers(),
                json=fixture.registration,
            )
        )
        fixture.login_request = request
        fixture.session = json_response(
            client.post(
                f"/api/v1/logins/{request['request_id']}/session",
                headers={**bearer(request["poll_token"]), "X-Request-ID": "a" * 64},
            )
        )

        # Leave one login grant and a different device's refresh retry in storage.
        _, _, second_session = start_login(client, "第二设备-登录", "b" * 64)
        fixture.refresh_seed = second_session["refresh_token"]
        refresh_headers = {
            **bearer(fixture.refresh_seed),
            "X-Request-ID": "c" * 64,
        }
        json_response(client.post("/api/v1/sessions/refresh", headers=refresh_headers))

        image = Image.new("RGBA", (64, 64), (24, 112, 76, 170))
        image.putpixel((17, 23), (255, 120, 34, 255))
        output = io.BytesIO()
        image.save(output, format="PNG")
        uploaded = json_response(
            client.put(
                "/api/v1/me/profile/skin",
                headers=bearer(fixture.session["management_token"]),
                files={"image": ("skin.png", output.getvalue(), "image/png")},
                data={"model": "slim"},
            )
        )
        fixture.skin_hash = uploaded["hash"]
        fixture.skin_bytes = client.get("/textures/" + fixture.skin_hash).content
        renamed = json_response(
            client.post(
                "/internal/v1/profiles/rename",
                headers=bot_headers(),
                json=event("改名-事件", name="AliceNew"),
            )
        )
        if renamed["uuid"] != fixture.registered["uuid"]:
            raise AssertionError("The Python fixture changed UUID during rename")

        fixture.profile = json_response(
            client.get(
                "/api/v1/game/profile",
                headers=bearer(fixture.session["game"]["accessToken"]),
            )
        )
        fixture.public_key = client.get("/api/yggdrasil").json()["signaturePublickey"]
        fixture.login_retry = json_response(
            client.post(
                f"/api/v1/logins/{request['request_id']}/session",
                headers={**bearer(request["poll_token"]), "X-Request-ID": "a" * 64},
            )
        )
        fixture.refresh_retry = json_response(
            client.post("/api/v1/sessions/refresh", headers=refresh_headers)
        )
        json_response(
            client.post("/api/v1/registrations", json={"name": "Reserved"}), 201
        )
        reference.backup_data(client.app.state.db, fixture.archive)
    return fixture


def database_rows(path, tables):
    rows = {}
    with closing(
        sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    ) as connection:
        connection.row_factory = sqlite3.Row
        for table in tables:
            records = [
                dict(record) for record in connection.execute(f"SELECT * FROM {table}")
            ]
            rows[table] = sorted(
                json.dumps(record, sort_keys=True, ensure_ascii=False)
                for record in records
            )
    return rows


def assert_snapshot(reference, fixture, restored):
    source = database_rows(fixture.data_dir / "nomi-auth.sqlite3", reference.tables)
    target = database_rows(restored / "nomi-auth.sqlite3", reference.tables)
    if source != target:
        changed = [name for name in source if source[name] != target[name]]
        raise AssertionError("Snapshot values changed in tables: " + ", ".join(changed))
    for relative in ["texture-signing.pem", "textures/" + fixture.skin_hash]:
        if (fixture.data_dir / relative).read_bytes() != (
            restored / relative
        ).read_bytes():
            raise AssertionError("Snapshot changed " + relative)
    return sum(len(records) for records in source.values())


class RustProcess:
    def __init__(self, binary: Path, root: Path):
        self.binary = binary
        self.root = root

    def environment(self, data_dir):
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("NOMI_")
        }
        environment.update(
            NOMI_DATA_DIR=str(data_dir),
            NOMI_DATABASE_BACKEND="sqlite",
            NOMI_PUBLIC_URL="http://auth.test",
            NOMI_BOT_TOKEN="x" * 32,
            NOMI_BOT_APP_ID="app",
            NOMI_GROUP_OPENID="group",
            NOMI_RENAME_COOLDOWN="0",
            RUST_LOG="error",
        )
        return environment

    def command(self, data_dir, *arguments):
        result = subprocess.run(
            [str(self.binary), *map(str, arguments)],
            cwd=self.root,
            env=self.environment(data_dir),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        if result.returncode:
            raise AssertionError(
                f"Rust {arguments[0]} command failed ({result.returncode}): {result.stderr.strip()}"
            )

    @contextmanager
    def client(self, data_dir):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        with tempfile.TemporaryFile(mode="w+") as log:
            process = subprocess.Popen(
                [str(self.binary), "serve", "--host", "127.0.0.1", "--port", str(port)],
                cwd=self.root,
                env=self.environment(data_dir),
                stdout=log,
                stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            try:
                with httpx.Client(
                    base_url=f"http://127.0.0.1:{port}", timeout=10, trust_env=False
                ) as client:
                    deadline = time.monotonic() + 20
                    while True:
                        if process.poll() is not None:
                            raise AssertionError(
                                "Rust server exited before becoming healthy"
                            )
                        try:
                            if client.get("/health").status_code == 200:
                                break
                        except httpx.ConnectError:
                            pass
                        if time.monotonic() >= deadline:
                            raise AssertionError("Rust server did not become healthy")
                        time.sleep(0.05)
                    yield client
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)


def check_signature(client, fixture):
    metadata = json_response(client.get("/api/yggdrasil"))
    if metadata["signaturePublickey"] != fixture.public_key:
        raise AssertionError("The migrated server changed its signing identity")
    response = json_response(
        client.get(
            "/api/yggdrasil/sessionserver/session/minecraft/profile/"
            + fixture.profile["id"],
            params={"unsigned": "false"},
        )
    )
    texture = next(
        item for item in response["properties"] if item["name"] == "textures"
    )
    public_key = serialization.load_pem_public_key(fixture.public_key.encode())
    public_key.verify(
        base64.b64decode(texture["signature"]),
        texture["value"].encode(),
        padding.PKCS1v15(),
        hashes.SHA1(),
    )
    payload = json.loads(base64.b64decode(texture["value"]))
    if payload["profileId"] != fixture.profile["id"]:
        raise AssertionError("Signed textures changed the profile UUID")
    if payload["textures"]["SKIN"]["metadata"]["model"] != "slim":
        raise AssertionError("Signed textures changed the skin model")
    if client.get("/textures/" + fixture.skin_hash).content != fixture.skin_bytes:
        raise AssertionError("The existing skin bytes changed")


def check_python_credentials(client, fixture):
    if (
        client.post(
            "/api/yggdrasil/authserver/validate", json=fixture.session["game"]
        ).status_code
        != 204
    ):
        raise AssertionError("Rust rejected an existing Python game credential")
    profile = json_response(
        client.get(
            "/api/v1/game/profile",
            headers=bearer(fixture.session["game"]["accessToken"]),
        )
    )
    if profile != fixture.profile:
        raise AssertionError("Rust changed the migrated game profile")
    replay = json_response(
        client.post(
            f"/api/v1/logins/{fixture.login_request['request_id']}/session",
            headers={
                **bearer(fixture.login_request["poll_token"]),
                "X-Request-ID": "a" * 64,
            },
        )
    )
    if replay != fixture.login_retry:
        raise AssertionError("Rust did not reproduce the stored Python login grant")
    replay = json_response(
        client.post(
            "/api/v1/sessions/refresh",
            headers={**bearer(fixture.refresh_seed), "X-Request-ID": "c" * 64},
        )
    )
    if replay != fixture.refresh_retry:
        raise AssertionError("Rust did not reproduce the stored Python refresh grant")
    claimed = json_response(
        client.post(
            "/internal/v1/logins/verify",
            headers=bot_headers(),
            json=fixture.verification,
        )
    )
    if claimed != {"status": "AWAITING_NAME"}:
        raise AssertionError("Rust did not read a stored Python verification receipt")
    registered = json_response(
        client.post(
            "/internal/v1/logins/register",
            headers=bot_headers(),
            json=fixture.registration,
        )
    )
    if registered != fixture.registered:
        raise AssertionError("Rust did not read a stored Python registration receipt")


def run(binary, reference_path):
    reference = PythonReference(reference_path)
    with tempfile.TemporaryDirectory(prefix="nomi-interop-") as temporary:
        root = Path(temporary)
        fixture = create_fixture(reference, root)
        rust = RustProcess(binary, root)

        restored = root / "rust-restored-python"
        rust.command(restored, "restore", fixture.archive, restored)
        row_count = assert_snapshot(reference, fixture, restored)
        rust_archive = root / "rust-backup.tar.gz"
        rust.command(restored, "backup", rust_archive)
        assert_snapshot(reference, fixture, restored)

        python_restored = root / "python-restored-rust"
        reference.restore_data(rust_archive, python_restored)
        assert_snapshot(reference, fixture, python_restored)

        http_data = root / "rust-http"
        shutil.copytree(python_restored, http_data)
        with rust.client(http_data) as client:
            check_python_credentials(client, fixture)
            check_signature(client, fixture)
            request, verification, session = start_login(
                client, "Rust-登录事件", "d" * 64
            )
            if session["game"]["selectedProfile"] != fixture.profile:
                raise AssertionError("A new Rust grant changed the migrated identity")
            _, _, refresh_seed = start_login(client, "Rust-刷新事件", "f" * 64)
            refresh_headers = {
                **bearer(refresh_seed["refresh_token"]),
                "X-Request-ID": "1" * 64,
            }
            refreshed = json_response(
                client.post("/api/v1/sessions/refresh", headers=refresh_headers)
            )

        python_data = root / "python-http"
        shutil.copytree(http_data, python_data)
        with reference.client(python_data) as client:
            if (
                client.post(
                    "/api/yggdrasil/authserver/validate", json=session["game"]
                ).status_code
                != 204
            ):
                raise AssertionError("Python rejected a Rust-issued credential")
            replay = json_response(
                client.post(
                    f"/api/v1/logins/{request['request_id']}/session",
                    headers={**bearer(request["poll_token"]), "X-Request-ID": "d" * 64},
                )
            )
            if replay != session:
                raise AssertionError("Python did not reproduce the Rust login grant")
            replayed_refresh = json_response(
                client.post("/api/v1/sessions/refresh", headers=refresh_headers)
            )
            if replayed_refresh != refreshed:
                raise AssertionError("Python did not reproduce the Rust refresh grant")
            verified = json_response(
                client.post(
                    "/internal/v1/logins/verify",
                    headers=bot_headers(),
                    json=verification,
                )
            )
            if verified["uuid"] != fixture.profile["id"]:
                raise AssertionError(
                    "Python could not read the Rust verification receipt"
                )
            json_response(
                client.post(
                    "/api/v1/sessions/refresh",
                    headers={
                        **bearer(session["refresh_token"]),
                        "X-Request-ID": "e" * 64,
                    },
                )
            )
            check_signature(client, fixture)

        assert_snapshot(reference, fixture, restored)
        print(
            json.dumps(
                {
                    "result": "passed",
                    "database_rows_verified": row_count,
                    "checks": [
                        "python_backup_to_rust_restore",
                        "rust_backup_to_python_restore",
                        "all_snapshot_fields_and_files",
                        "python_credentials_on_rust",
                        "python_receipt_and_retry_replay",
                        "rust_credentials_on_python",
                        "rust_receipt_and_retry_replay",
                        "persistent_rsa_signatures",
                    ],
                }
            )
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--neo-binary", type=Path, required=True)
    parser.add_argument(
        "--python-reference",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "nomi-auth",
    )
    arguments = parser.parse_args()
    binary = arguments.neo_binary.resolve()
    reference = arguments.python_reference.resolve()
    if not binary.is_file() or not (reference / "src" / "app.py").is_file():
        parser.error("Provide an existing neo executable and Python reference checkout")
    run(binary, reference)


if __name__ == "__main__":
    main()
