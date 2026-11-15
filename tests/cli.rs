use std::{fs, process::Command};

fn executable() -> std::path::PathBuf {
    // Cross-built tests can point at a native executable without copying it.
    std::env::var_os("NOMI_TEST_BINARY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_nomi-auth-neo").into())
}

fn run(directory: &std::path::Path, arguments: &[&str]) -> std::process::Output {
    let mut command = Command::new(executable());
    command.current_dir(directory).args(arguments);
    for (name, _) in std::env::vars_os() {
        if name
            .to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("NOMI_")
        {
            command.env_remove(name);
        }
    }
    command.output().unwrap()
}

struct Service {
    process: std::process::Child,
    address: std::net::SocketAddr,
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

impl Service {
    fn start(directory: &std::path::Path) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let mut command = Command::new(executable());
        command
            .current_dir(directory)
            .args(["serve", "--port", &address.port().to_string()]);
        for (name, _) in std::env::vars_os() {
            if name
                .to_string_lossy()
                .to_ascii_uppercase()
                .starts_with("NOMI_")
            {
                command.env_remove(name);
            }
        }
        let process = command
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut service = Self { process, address };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            assert!(
                service.process.try_wait().unwrap().is_none(),
                "Standalone service exited during startup"
            );
            if let Ok(response) = service
                .request("GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                && response.starts_with("HTTP/1.1 200")
            {
                return service;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "Standalone service failed to start"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    fn request(&self, request: &str) -> std::io::Result<String> {
        use std::io::{Read, Write};
        let mut stream =
            std::net::TcpStream::connect_timeout(&self.address, std::time::Duration::from_secs(1))?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
        stream.write_all(request.as_bytes())?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
    }
}

#[test]
fn no_arguments_print_help_without_reading_or_creating_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(directory.path(), &[]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("Commands:"));
    assert!(help.contains("Start the authentication HTTP service"));
    assert!(!directory.path().join(".env").exists());
    assert!(!directory.path().join("data").exists());

    fs::write(directory.path().join(".env"), "invalid settings").unwrap();
    assert!(run(directory.path(), &[]).status.success());
    assert!(!directory.path().join("data").exists());
    for command in [
        "serve",
        "backup",
        "restore",
        "cleanup",
        "enable",
        "disable",
        "delete",
        "migrate-database",
        "login",
    ] {
        let output = run(directory.path(), &[command, "--help"]);
        assert!(output.status.success(), "Missing help for {command}");
    }
}

#[test]
fn standalone_first_start_generates_configuration_and_exits_before_serving() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(directory.path(), &["serve"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Edit .env"));
    let configuration = directory.path().join(".env");
    let values: std::collections::HashMap<_, _> = dotenvy::from_path_iter(&configuration)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(values["NOMI_BOT_TOKEN"].len() >= 32);
    assert!(!values["NOMI_BOT_TOKEN"].contains("replace"));
    assert_eq!(values["NOMI_BOT_APP_ID"], "");
    assert_eq!(values["NOMI_GROUP_OPENID"], "");
    assert_eq!(values["NOMI_GROUP_LABEL"], "Server Group");
    assert!(!directory.path().join("data").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&configuration).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let original = fs::read(&configuration).unwrap();
    assert!(!run(directory.path(), &["serve"]).status.success());
    assert_eq!(fs::read(&configuration).unwrap(), original);
    let edited = String::from_utf8(original)
        .unwrap()
        .replace("NOMI_BOT_APP_ID=", "NOMI_BOT_APP_ID=test-app")
        .replace("NOMI_GROUP_OPENID=", "NOMI_GROUP_OPENID=test-group");
    fs::write(&configuration, &edited).unwrap();
    let service = Service::start(directory.path());
    assert!(directory.path().join("data/nomi-auth.sqlite3").is_file());
    assert_eq!(fs::read_to_string(&configuration).unwrap(), edited);
    drop(service);
    let other = tempfile::tempdir().unwrap();
    assert!(run(other.path(), &["serve"]).status.success());
    assert!(!other.path().join("data").exists());
    let second: std::collections::HashMap<_, _> =
        dotenvy::from_path_iter(other.path().join(".env"))
            .unwrap()
            .map(Result::unwrap)
            .collect();
    assert_ne!(values["NOMI_BOT_TOKEN"], second["NOMI_BOT_TOKEN"]);
}

#[test]
fn existing_configuration_is_never_replaced() {
    let directory = tempfile::tempdir().unwrap();
    let configuration = directory.path().join(".env");
    fs::write(&configuration, "NOMI_BOT_TOKEN=keep-this-value\n").unwrap();
    let original = fs::read(&configuration).unwrap();
    assert!(!run(directory.path(), &["serve"]).status.success());
    assert_eq!(fs::read(&configuration).unwrap(), original);
}

#[test]
fn informational_and_maintenance_commands_do_not_generate_configuration() {
    let directory = tempfile::tempdir().unwrap();
    assert!(run(directory.path(), &["--version"]).status.success());
    assert!(!directory.path().join(".env").exists());
    assert!(!run(directory.path(), &["cleanup"]).status.success());
    assert!(!directory.path().join(".env").exists());
}

#[test]
fn local_admin_can_approve_a_launcher_code_without_an_http_admin_endpoint() {
    let directory = tempfile::tempdir().unwrap();
    assert!(run(directory.path(), &["serve"]).status.success());
    let configuration = directory.path().join(".env");
    let edited = fs::read_to_string(&configuration)
        .unwrap()
        .replace("NOMI_BOT_APP_ID=", "NOMI_BOT_APP_ID=test-app")
        .replace("NOMI_GROUP_OPENID=", "NOMI_GROUP_OPENID=test-group");
    fs::write(&configuration, &edited).unwrap();
    let service = Service::start(directory.path());
    let response = service.request("POST /api/v1/logins HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").unwrap();
    let login: serde_json::Value =
        serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();

    let output = run(
        directory.path(),
        &["login", login["code"].as_str().unwrap(), "AdminTest"],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Login approved: AdminTest"));
    assert_eq!(fs::read_to_string(configuration).unwrap(), edited);

    let request = format!(
        "POST /api/v1/logins/{}/session HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        login["request_id"].as_str().unwrap(),
        login["poll_token"].as_str().unwrap()
    );
    let response = service.request(&request).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    let session: serde_json::Value =
        serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(session["game"]["selectedProfile"]["name"], "AdminTest");
    let response = service.request("POST /api/v1/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
    assert!(response.starts_with("HTTP/1.1 404"));
    assert!(
        !run(
            directory.path(),
            &["login", login["code"].as_str().unwrap(), "AnotherTest"]
        )
        .status
        .success()
    );
    let refused = run(directory.path(), &["delete", "AdminTest"]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("Disable it before deleting"));
    let request = format!(
        "GET /api/v1/game/profile HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
        session["game"]["accessToken"].as_str().unwrap()
    );
    assert!(
        service
            .request(&request)
            .unwrap()
            .starts_with("HTTP/1.1 200")
    );
    assert!(
        run(directory.path(), &["disable", "AdminTest"])
            .status
            .success()
    );
    let deleted = run(directory.path(), &["delete", "admintest"]);
    assert!(
        deleted.status.success(),
        "{}",
        String::from_utf8_lossy(&deleted.stderr)
    );
    assert!(String::from_utf8_lossy(&deleted.stdout).contains("Account AdminTest: deleted"));
    assert!(
        !run(directory.path(), &["delete", "AdminTest"])
            .status
            .success()
    );
    let request = format!(
        "GET /api/v1/game/profile HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
        session["game"]["accessToken"].as_str().unwrap()
    );
    assert!(
        service
            .request(&request)
            .unwrap()
            .starts_with("HTTP/1.1 403")
    );
}
