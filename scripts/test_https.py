"""Test HTTPS integration with temporary TLS identities and an isolated proxy."""

import argparse
import asyncio
import importlib
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import types
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

TOKEN = "temporary-test-token-" + "x" * 32


def issue_certificate(directory, name, authority=None, purpose=None, expired=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    issuer, signer = (subject, key) if authority is None else authority
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(
            now - timedelta(days=1) if expired else now + timedelta(days=7)
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()),
            False,
        )
        .add_extension(
            x509.BasicConstraints(ca=authority is None, path_length=None), True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=authority is not None,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=authority is None,
                crl_sign=authority is None,
                encipher_only=False,
                decipher_only=False,
            ),
            True,
        )
    )
    if purpose is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage([purpose]), False)
    if purpose == ExtendedKeyUsageOID.SERVER_AUTH:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            False,
        )
    certificate = builder.sign(signer, hashes.SHA256())
    (directory / f"{name}.pem").write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM)
    )
    key_path = directory / f"{name}-key.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    return subject, key


def available_ports():
    with socket.socket() as backend, socket.socket() as gateway:
        for listener in (backend, gateway):
            listener.bind(("127.0.0.1", 0))
        return (
            backend.getsockname()[1],
            gateway.getsockname()[1],
            gateway.getsockname()[1],
        )


def nginx_configuration(directory, ports):
    backend, gateway, _ = ports
    block = f"""server {{
    listen 127.0.0.1:{gateway} ssl;
    server_name localhost;
    ssl_certificate {directory}/server.pem;
    ssl_certificate_key {directory}/server-key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    location / {{
        proxy_pass http://127.0.0.1:{backend};
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Forwarded "";
    }}
}}
"""
    configuration = (
        f"pid {directory}/nginx.pid;\nerror_log {directory}/nginx-error.log warn;\n"
        "worker_processes 1;\nevents { worker_connections 64; }\nhttp {\n"
        "access_log off;\n"
        f"client_body_temp_path {directory}/client-body;\n"
        f"proxy_temp_path {directory}/proxy;\n" + block + "\n}\n"
    )
    path = directory / "nginx.conf"
    path.write_text(configuration, encoding="utf-8")
    return path


def tls_context(directory):
    return ssl.create_default_context(cafile=directory / "server-ca.pem")


@contextmanager
def processes(binary, nginx, directory):
    ports = available_ports()
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("NOMI_")
    }
    environment.update(
        NOMI_PUBLIC_URL=f"https://127.0.0.1:{ports[1]}",
        NOMI_DATA_DIR=str(directory / "data"),
        NOMI_DATABASE_BACKEND="sqlite",
        NOMI_BOT_APP_ID="test-app",
        NOMI_GROUP_OPENID="test-group",
        NOMI_BOT_TOKEN=TOKEN,
        RUST_LOG="error",
    )
    # The isolated service receives its complete configuration through environment values.
    (directory / ".env").write_text("", encoding="utf-8")
    configuration = nginx_configuration(directory, ports)
    subprocess.run(
        [str(nginx), "-p", str(directory), "-c", str(configuration), "-t"],
        check=True,
        capture_output=True,
    )
    running = []
    try:
        with (directory / "process.log").open("wb") as output:
            commands = [
                [str(binary), "serve", "--host", "127.0.0.1", "--port", str(ports[0])],
                [
                    str(nginx),
                    "-p",
                    str(directory),
                    "-c",
                    str(configuration),
                    "-g",
                    "daemon off;",
                ],
            ]
            for command in commands:
                running.append(
                    subprocess.Popen(
                        command,
                        env=environment,
                        cwd=directory,
                        stdout=output,
                        stderr=output,
                    )
                )
            with httpx.Client(verify=tls_context(directory), trust_env=False) as client:
                last_response = "no response"
                for _ in range(200):
                    if any(process.poll() is not None for process in running):
                        raise AssertionError(
                            "A temporary service exited during startup"
                        )
                    try:
                        response = client.get(f"https://127.0.0.1:{ports[1]}/health")
                        last_response = str(response.status_code)
                        if response.status_code == 200:
                            break
                    except httpx.HTTPError as error:
                        last_response = str(error)
                    time.sleep(0.05)
                else:
                    raise AssertionError(
                        "Temporary NGINX and auth service did not become ready: "
                        + last_response
                        + "; "
                        + (directory / "nginx-error.log").read_text()[-2000:]
                    )
            yield ports
    finally:
        for process in reversed(running):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def expect(response, status):
    if response.status_code != status:
        raise AssertionError(
            f"{response.request.method} {response.request.url.path}: expected {status}, got {response.status_code}"
        )
    if response.headers.get("content-type", "").startswith("application/json"):
        return response.json()
    return None


def member_event(event_id, **fields):
    return {
        "bot_app_id": "test-app",
        "group_openid": "test-group",
        "member_openid": "test-member",
        "event_id": event_id,
        **fields,
    }


def exercise(directory, ports):
    backend, public, internal = ports
    public_url = f"https://127.0.0.1:{public}"
    internal_url = f"https://127.0.0.1:{internal}"
    if public != internal:
        raise AssertionError(
            "Public and internal requests must use the same TLS listener"
        )
    authorization = {"Authorization": "Bearer " + TOKEN}
    with (
        httpx.Client(
            base_url=public_url, verify=tls_context(directory), trust_env=False
        ) as public_client,
        httpx.Client(
            base_url=internal_url,
            verify=tls_context(directory),
            trust_env=False,
        ) as bot,
    ):
        expect(public_client.get("/health"), 200)
        expect(bot.get("/health"), 200)
        for path in (
            "/internal",
            "/internal/v1/logins/verify",
            "/%69nternal/v1/logins/verify",
        ):
            response = public_client.post(
                path,
                json=member_event("forged", code="AAAA-BBBB-CCCC"),
                headers={
                    "X-Nomi-Client-Verify": "SUCCESS",
                    "X-Forwarded-For": "127.0.0.1",
                },
            )
            if response.status_code != (404 if path == "/internal" else 401):
                raise AssertionError(
                    "Forged proxy headers bypassed secret authentication"
                )
        with httpx.Client(
            base_url=f"http://127.0.0.1:{backend}", trust_env=False
        ) as direct:
            expect(
                direct.post(
                    "/internal/v1/logins/verify",
                    json=member_event("direct", code="AAAA-BBBB-CCCC"),
                ),
                401,
            )
        request = expect(public_client.post("/api/v1/logins", json={}), 201)
        payload = member_event("verify-new", code=request["code"])
        expect(
            bot.post(
                "/internal/v1/logins/verify",
                json=payload,
                headers={"Authorization": "Bearer wrong-token"},
            ),
            401,
        )
        claimed = expect(
            bot.post(
                "/internal/v1/logins/verify",
                json=payload,
                headers={**authorization, "X-Nomi-Client-Verify": "FAILED"},
            ),
            200,
        )
        if claimed != {"status": "AWAITING_NAME"}:
            raise AssertionError("A trusted robot could not claim a new registration")
        registered = expect(
            bot.post(
                "/internal/v1/logins/register",
                json=member_event("register", name="HttpsPlayer"),
                headers=authorization,
            ),
            200,
        )
        if registered["name"] != "HttpsPlayer":
            raise AssertionError("The trusted registration returned the wrong ID")
        session = expect(
            public_client.post(
                f"/api/v1/logins/{request['request_id']}/session",
                headers={
                    "Authorization": "Bearer " + request["poll_token"],
                    "X-Request-ID": "a" * 64,
                },
            ),
            200,
        )
        if session["game"]["selectedProfile"]["id"] != registered["uuid"]:
            raise AssertionError(
                "The public session did not use the registered identity"
            )
        second = expect(public_client.post("/api/v1/logins", json={}), 201)
        logged_in = expect(
            bot.post(
                "/internal/v1/logins/verify",
                json=member_event("verify-existing", code=second["code"]),
                headers=authorization,
            ),
            200,
        )
        if logged_in["status"] != "VERIFIED" or logged_in["uuid"] != registered["uuid"]:
            raise AssertionError("The trusted existing-account login failed")
    return [
        "https_registration_and_login",
        "wrong_bearer",
        "same_domain_and_port_public_api",
        "forged_proxy_headers",
        "backend_missing_secret",
    ]


async def exercise_plugin(directory, ports, reference):
    # Import the real client modules without registering live NoneBot handlers.
    package = types.ModuleType("_https_nomi_plugin")
    package.__path__ = [str(reference / "src" / "nomi_auth_plugin")]
    sys.modules[package.__name__] = package
    client_module = importlib.import_module(package.__name__ + ".client")
    config_module = importlib.import_module(package.__name__ + ".config")
    error_module = importlib.import_module(package.__name__ + ".errors")
    config = config_module.Config(
        nomi_auth_base_url=f"https://127.0.0.1:{ports[2]}",
        nomi_bot_api_token=TOKEN,
        nomi_bot_app_id="test-app",
        nomi_allowed_group_openid="test-group",
        nomi_tls_ca_cert=str(directory / "server-ca.pem"),
    )
    bot = client_module.AuthClient(config)
    invalid_bot = client_module.AuthClient(
        config.model_copy(update={"nomi_bot_api_token": "wrong-" + "x" * 32})
    )
    try:
        async with httpx.AsyncClient(
            base_url=f"https://127.0.0.1:{ports[1]}",
            verify=tls_context(directory),
            trust_env=False,
        ) as client:
            request = expect(await client.post("/api/v1/logins", json={}), 201)
            try:
                await invalid_bot.submit(
                    "登录",
                    request["code"],
                    "test-group",
                    "plugin-member",
                    "plugin-wrong-token",
                )
            except error_module.BackendError:
                pass
            else:
                raise AssertionError("The real plugin accepted the wrong Bearer token")
            claimed = await bot.submit(
                "登录", request["code"], "test-group", "plugin-member", "plugin-claim"
            )
            if claimed != {"status": "AWAITING_NAME"}:
                raise AssertionError("The real plugin could not claim registration")
            registered = await bot.submit(
                "注册", "PluginPlayer", "test-group", "plugin-member", "plugin-register"
            )
            session = expect(
                await client.post(
                    f"/api/v1/logins/{request['request_id']}/session",
                    headers={
                        "Authorization": "Bearer " + request["poll_token"],
                        "X-Request-ID": "b" * 64,
                    },
                ),
                200,
            )
            renamed = await bot.submit(
                "改名", "PluginRenamed", "test-group", "plugin-member", "plugin-rename"
            )
            if (
                registered["uuid"] != session["game"]["selectedProfile"]["id"]
                or renamed["uuid"] != registered["uuid"]
                or renamed["name"] != "PluginRenamed"
            ):
                raise AssertionError(
                    "The real plugin rename changed identity or failed"
                )
            second = expect(await client.post("/api/v1/logins", json={}), 201)
            logged_in = await bot.submit(
                "登录", second["code"], "test-group", "plugin-member", "plugin-login"
            )
            if (
                logged_in["status"] != "VERIFIED"
                or logged_in["uuid"] != registered["uuid"]
            ):
                raise AssertionError("The real plugin could not log in after rename")
    finally:
        await invalid_bot.close()
        await bot.close()
    return ["actual_plugin_login_register_rename", "actual_plugin_wrong_bearer"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--neo-binary", type=Path, required=True)
    parser.add_argument("--nginx", type=Path, default=Path("/usr/sbin/nginx"))
    parser.add_argument("--plugin-reference", type=Path)
    arguments = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="nomi-https-") as temporary:
        directory = Path(temporary)
        server_ca = issue_certificate(directory, "server-ca")
        issue_certificate(
            directory, "server", server_ca, ExtendedKeyUsageOID.SERVER_AUTH
        )
        with processes(
            arguments.neo_binary.resolve(),
            arguments.nginx.resolve(),
            directory,
        ) as ports:
            checks = exercise(directory, ports)
            if arguments.plugin_reference is not None:
                checks += asyncio.run(
                    exercise_plugin(
                        directory, ports, arguments.plugin_reference.resolve()
                    )
                )
            print(json.dumps({"result": "passed", "checks": checks}))


if __name__ == "__main__":
    main()
