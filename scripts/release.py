"""Validate main-branch tags, smoke-test executables and prepare release archives."""

import argparse
import json
import os
import re
import socket
import subprocess
import tarfile
import tempfile
import time
import tomllib
import urllib.request
import zipfile
from pathlib import Path

VERSION = re.compile(
    r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
PLATFORMS = {"linux-x86_64": "nomi-auth-neo", "windows-x86_64": "nomi-auth-neo.exe"}


def git(*arguments: str, directory: Path) -> str:
    return subprocess.check_output(
        ["git", *arguments], cwd=directory, text=True, timeout=30
    ).strip()


def validate(directory: Path, tag: str | None = None) -> str:
    with (directory / "Cargo.toml").open("rb") as source:
        version = tomllib.load(source)["package"]["version"]
    if not VERSION.fullmatch(version):
        raise ValueError("Package version must be a semantic version")
    if tag is not None:
        if tag != "v" + version:
            raise ValueError("Tag must equal v followed by the Cargo package version")
        commit = git(
            "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}", directory=directory
        )
        if commit != git("rev-parse", "HEAD", directory=directory):
            raise ValueError("The checkout must match the tagged commit")
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", commit, "origin/main"],
            cwd=directory,
            check=False,
            timeout=30,
        )
        if result.returncode:
            raise ValueError("The tagged commit must belong to origin/main")
    return version


def smoke(binary: Path, version: str) -> None:
    binary = binary.resolve()
    output = subprocess.check_output([str(binary), "--version"], text=True, timeout=15)
    if output.strip() != f"nomi-auth-neo {version}":
        raise ValueError("Executable version does not match the release")
    with tempfile.TemporaryDirectory(prefix="nomi-release-") as temporary:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.upper().startswith("NOMI_")
        }
        environment.update(
            NOMI_DATA_DIR=str(Path(temporary) / "data"),
            NOMI_BOT_TOKEN="release-smoke-test-" + "x" * 32,
            NOMI_BOT_APP_ID="release-test-app",
            NOMI_GROUP_OPENID="release-test-group",
        )
        initial = subprocess.run(
            [str(binary)],
            check=False,
            cwd=temporary,
            env=environment,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if initial.returncode != 0 or not (Path(temporary) / ".env").is_file():
            raise ValueError("First startup did not generate configuration and exit")
        if (Path(temporary) / "data").exists():
            raise ValueError("First startup created data before configuration")
        with tempfile.TemporaryFile() as log:
            process = subprocess.Popen(
                [str(binary), "serve", "--host", "127.0.0.1", "--port", str(port)],
                cwd=temporary,
                env=environment,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            try:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError(
                            "Release executable exited before becoming ready"
                        )
                    try:
                        with opener.open(
                            f"http://127.0.0.1:{port}/health", timeout=1
                        ) as response:
                            if response.status == 200:
                                break
                    except OSError:
                        time.sleep(0.1)
                else:
                    raise TimeoutError("Release executable did not become ready")
                request = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/v1/logins",
                    data=b"{}",
                    headers={"Content-Type": "application/json"},
                )
                with opener.open(request, timeout=10) as response:
                    payload = json.load(response)
                    if (
                        response.status != 201
                        or not payload.get("code")
                        or not payload.get("poll_token")
                    ):
                        raise ValueError(
                            "Release executable could not create a login request"
                        )
                if not (Path(temporary) / "data/nomi-auth.sqlite3").is_file():
                    raise ValueError(
                        "Release executable did not create its SQLite database"
                    )
            except Exception:
                log.seek(0)
                print(log.read().decode(errors="replace"))
                raise
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
    print("Executable version, startup, SQLite and login smoke checks passed")


def package(
    directory: Path, binary: Path, platform: str, notices: Path, destination: Path
) -> Path:
    files = {
        PLATFORMS[platform]: binary,
        "README.md": directory / "README.md",
        "CONTRIBUTING.md": directory / "CONTRIBUTING.md",
        "API.md": directory / "API.md",
        "THIRD_PARTY_NOTICES.md": notices,
    }
    for path in files.values():
        if not path.is_file():
            raise FileNotFoundError(path)
    destination.mkdir(parents=True, exist_ok=True)
    if platform == "windows-x86_64":
        output = destination / "nomi-auth-neo-windows-x86_64.zip"
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, path in files.items():
                archive.write(path, name)
    else:
        output = destination / "nomi-auth-neo-linux-x86_64.tar.gz"
        with tarfile.open(output, "w:gz") as archive:
            for name, path in files.items():
                entry = archive.gettarinfo(str(path), name)
                entry.mode = 0o755 if name == PLATFORMS[platform] else 0o644
                entry.uid = entry.gid = 0
                entry.uname = entry.gname = ""
                with path.open("rb") as source:
                    archive.addfile(entry, source)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    gate = commands.add_parser("validate")
    gate.add_argument("--tag")
    commands.add_parser("smoke").add_argument("binary", type=Path)
    packing = commands.add_parser("package")
    packing.add_argument("binary", type=Path)
    packing.add_argument("--platform", choices=PLATFORMS, required=True)
    packing.add_argument("--notices", type=Path, required=True)
    packing.add_argument("--destination", type=Path, default=Path("artifacts/release"))
    arguments = parser.parse_args()
    directory = Path.cwd()
    if arguments.command == "validate":
        version = validate(directory, arguments.tag)
        if output := os.environ.get("GITHUB_OUTPUT"):
            with Path(output).open("a", encoding="utf-8") as stream:
                stream.write(
                    f"version={version}\nprerelease={'true' if '-' in version.split('+')[0] else 'false'}\n"
                )
        print(version)
    elif arguments.command == "smoke":
        smoke(arguments.binary, validate(directory))
    else:
        print(
            package(
                directory,
                arguments.binary,
                arguments.platform,
                arguments.notices,
                arguments.destination,
            )
        )


if __name__ == "__main__":
    main()
