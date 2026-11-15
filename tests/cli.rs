use std::{fs, process::Command};

fn run(directory: &std::path::Path, arguments: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nomi-auth-neo"));
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

#[test]
fn first_start_generates_private_configuration_and_waits_for_required_fields() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(directory.path(), &[]);
    assert!(!output.status.success());
    let configuration = directory.path().join(".env");
    let values: std::collections::HashMap<_, _> = dotenvy::from_path_iter(&configuration)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(values["NOMI_BOT_TOKEN"].len() >= 32);
    assert!(!values["NOMI_BOT_TOKEN"].contains("replace"));
    assert_eq!(values["NOMI_BOT_APP_ID"], "");
    assert_eq!(values["NOMI_GROUP_OPENID"], "");
    assert!(String::from_utf8_lossy(&output.stderr).contains(".env"));
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
    let other = tempfile::tempdir().unwrap();
    run(other.path(), &[]);
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
