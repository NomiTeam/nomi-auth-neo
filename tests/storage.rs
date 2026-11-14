use std::{fs, path::Path, sync::Arc, time::Duration};

use nomi_auth_neo::{
    core::Settings,
    storage::{Database, maintenance, transfer},
};
use rsa::{
    RsaPrivateKey,
    pkcs8::{EncodePrivateKey, LineEnding},
};
use sha2::{Digest, Sha256};
use sqlx::Row;
use tempfile::TempDir;

async fn database() -> (TempDir, Arc<Database>) {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings {
        data_dir: directory.path().join("data"),
        ..Settings::default()
    };
    let database = Database::open(&settings).await.unwrap();
    (directory, database)
}

fn write_key(database: &Database) {
    let key = RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
    fs::write(
        database.data_dir().join("texture-signing.pem"),
        key.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
}

async fn account(database: &Database, profile_id: &str, skin: Option<&str>) {
    let mut transaction = database.write().await.unwrap();
    sqlx::query("INSERT INTO accounts VALUES('account','Alice','alice','active',9000000000)")
        .execute(transaction.connection())
        .await
        .unwrap();
    sqlx::query("INSERT INTO profiles(uuid,account_id,name,name_normalized,skin_hash) VALUES(?,'account','Alice','alice',?)")
        .bind(profile_id).bind(skin).execute(transaction.connection()).await.unwrap();
    sqlx::query("INSERT INTO identities VALUES('account','app','group','member')")
        .execute(transaction.connection())
        .await
        .unwrap();
    transaction.commit().await.unwrap();
}

async fn count(database: &Database, table: &str) -> i64 {
    sqlx::query(&format!("SELECT COUNT(*) FROM {table}"))
        .fetch_one(database.pool())
        .await
        .unwrap()
        .try_get(0)
        .unwrap()
}

#[tokio::test]
async fn sqlite_initialization_and_cancelled_writer_preserve_atomicity() {
    let (_directory, database) = database().await;
    assert_eq!(count(&database, "accounts").await, 0);
    let mut first = database.write().await.unwrap();
    sqlx::query("INSERT INTO accounts VALUES('temporary','Temp','temp','active',1)")
        .execute(first.connection())
        .await
        .unwrap();
    drop(first);

    let mut next = tokio::time::timeout(Duration::from_secs(5), database.write())
        .await
        .unwrap()
        .unwrap();
    assert!(
        sqlx::query("SELECT id FROM accounts")
            .fetch_optional(next.connection())
            .await
            .unwrap()
            .is_none()
    );
    sqlx::query("INSERT INTO accounts VALUES('permanent','Alice','alice','active',1)")
        .execute(next.connection())
        .await
        .unwrap();
    next.commit().await.unwrap();
    assert_eq!(count(&database, "accounts").await, 1);
    database.pool().close().await;
}

#[tokio::test]
async fn newer_sqlite_schema_is_rejected_without_changing_source_bytes() {
    let (_directory, database) = database().await;
    let path = database.data_dir().join("nomi-auth.sqlite3");
    let mut transaction = database.write().await.unwrap();
    sqlx::query("INSERT INTO schema_versions VALUES(6)")
        .execute(transaction.connection())
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    database.pool().close().await;
    let before = fs::read(&path).unwrap();
    let settings = Settings {
        data_dir: database.data_dir().to_owned(),
        ..Settings::default()
    };
    assert!(Database::open(&settings).await.is_err());
    assert_eq!(fs::read(path).unwrap(), before);
}

#[tokio::test]
async fn legacy_sqlite_upgrade_preserves_identity_and_removes_password_storage() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nomi-auth.sqlite3");
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}?mode=rwc", path.display()))
        .await
        .unwrap();
    let schema = "
        CREATE TABLE schema_versions(version INTEGER PRIMARY KEY);
        INSERT INTO schema_versions VALUES(1);
        CREATE TABLE accounts(id TEXT PRIMARY KEY, login_name TEXT NOT NULL, login_normalized TEXT UNIQUE,
          password_hash TEXT NOT NULL, status TEXT DEFAULT 'active', created_at INTEGER);
        INSERT INTO accounts VALUES('account','Alice','alice','legacy-hash','active',0);
        CREATE TABLE profiles(uuid TEXT PRIMARY KEY,account_id TEXT UNIQUE,name TEXT,name_normalized TEXT UNIQUE,
          skin_hash TEXT,skin_model TEXT DEFAULT 'default',last_renamed_at INTEGER);
        INSERT INTO profiles(uuid,account_id,name,name_normalized) VALUES('12345678901234567890123456789012','account','Alice','alice');
        CREATE TABLE identities(account_id TEXT UNIQUE,app_id TEXT,group_id TEXT,member_id TEXT,UNIQUE(app_id,group_id,member_id));
        INSERT INTO identities VALUES('account','app','group','member');
        CREATE TABLE registrations(id TEXT PRIMARY KEY,code_hash TEXT UNIQUE,poll_hash TEXT,name TEXT,
          password_hash TEXT,status TEXT DEFAULT 'PENDING',expires_at INTEGER,account_id TEXT,error TEXT);
        CREATE TABLE tokens(hash TEXT PRIMARY KEY,account_id TEXT NOT NULL REFERENCES accounts(id),kind TEXT NOT NULL,
          client_token TEXT,expires_at INTEGER NOT NULL);
        INSERT INTO tokens VALUES('password-token','account','game','old-client',9000000000);
    ";
    for statement in schema
        .split(';')
        .filter(|statement| !statement.trim().is_empty())
    {
        sqlx::query(statement).execute(&pool).await.unwrap();
    }
    pool.close().await;

    let database = Database::open(&Settings {
        data_dir: directory.path().to_owned(),
        ..Settings::default()
    })
    .await
    .unwrap();
    let profile: String = sqlx::query("SELECT uuid FROM profiles")
        .fetch_one(database.pool())
        .await
        .unwrap()
        .try_get(0)
        .unwrap();
    assert_eq!(profile, "12345678901234567890123456789012");
    assert_eq!(count(&database, "identities").await, 1);
    assert_eq!(count(&database, "tokens").await, 0);
    let columns = sqlx::query("PRAGMA table_info(accounts)")
        .fetch_all(database.pool())
        .await
        .unwrap();
    assert!(
        !columns
            .iter()
            .any(|record| record.try_get::<String, _>(1).unwrap() == "password_hash")
    );
    database.pool().close().await;
}

#[tokio::test]
async fn schema_four_upgrade_preserves_existing_refresh_credentials() {
    let (_directory, database) = database().await;
    account(&database, "original-profile", None).await;
    let mut transaction = database.write().await.unwrap();
    sqlx::query(
        "INSERT INTO tokens VALUES('existing-refresh','account','refresh','device',9000000000)",
    )
    .execute(transaction.connection())
    .await
    .unwrap();
    for statement in [
        "DROP TABLE login_retries",
        "DROP TABLE refresh_retries",
        "DELETE FROM schema_versions WHERE version=5",
    ] {
        sqlx::query(statement)
            .execute(transaction.connection())
            .await
            .unwrap();
    }
    transaction.commit().await.unwrap();
    database.pool().close().await;

    let upgraded = Database::open(&Settings {
        data_dir: database.data_dir().to_owned(),
        ..Settings::default()
    })
    .await
    .unwrap();
    let record = sqlx::query("SELECT hash,expires_at FROM tokens")
        .fetch_one(upgraded.pool())
        .await
        .unwrap();
    assert_eq!(record.try_get::<String, _>(0).unwrap(), "existing-refresh");
    assert_eq!(record.try_get::<i64, _>(1).unwrap(), 9000000000);
    assert_eq!(count(&upgraded, "profiles").await, 1);
    upgraded.pool().close().await;
}

#[tokio::test]
async fn cleanup_removes_expired_data_but_keeps_accounts_and_live_sessions() {
    let (_directory, database) = database().await;
    account(&database, "profile", None).await;
    let mut transaction = database.write().await.unwrap();
    for (hash, expiry) in [("expired", 10_i64), ("valid", 100000)] {
        sqlx::query("INSERT INTO tokens VALUES(?,'account','game','client',?)")
            .bind(hash)
            .bind(expiry)
            .execute(transaction.connection())
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO audit(action,created_at) VALUES('old',0)")
        .execute(transaction.connection())
        .await
        .unwrap();
    sqlx::query("INSERT INTO audit(action,created_at) VALUES('recent',80000)")
        .execute(transaction.connection())
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    database.cleanup_if_due(90000).await.unwrap();
    assert_eq!(count(&database, "tokens").await, 1);
    assert_eq!(count(&database, "accounts").await, 1);
    assert_eq!(count(&database, "profiles").await, 1);
    assert_eq!(count(&database, "audit").await, 1);
    let mut transaction = database.write().await.unwrap();
    sqlx::query("UPDATE tokens SET expires_at=0")
        .execute(transaction.connection())
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    database.cleanup_if_due(90001).await.unwrap();
    assert_eq!(count(&database, "tokens").await, 1);
    database.cleanup_if_due(90030).await.unwrap();
    assert_eq!(count(&database, "tokens").await, 0);
    database.pool().close().await;
}

#[tokio::test]
async fn portable_backup_restores_accounts_key_and_skin_without_overwriting() {
    let (directory, database) = database().await;
    write_key(&database);
    let skin = b"skin";
    let hash = hex::encode(Sha256::digest(skin));
    fs::create_dir(database.data_dir().join("textures")).unwrap();
    fs::write(database.data_dir().join("textures").join(&hash), skin).unwrap();
    account(&database, "profile", Some(&hash)).await;

    let archive = directory.path().join("backup.tar.gz");
    maintenance::backup_data(&database, &archive).await.unwrap();
    let first = fs::read(&archive).unwrap();
    assert!(maintenance::backup_data(&database, &archive).await.is_err());
    assert_eq!(fs::read(&archive).unwrap(), first);

    let destination = directory.path().join("restored");
    maintenance::restore_data(&archive, &destination)
        .await
        .unwrap();
    assert_eq!(
        fs::read(destination.join("textures").join(&hash)).unwrap(),
        skin
    );
    assert_eq!(
        fs::read(destination.join("texture-signing.pem")).unwrap(),
        fs::read(database.data_dir().join("texture-signing.pem")).unwrap()
    );
    assert!(
        maintenance::restore_data(&archive, &destination)
            .await
            .is_err()
    );
    let restored = Database::open(&Settings {
        data_dir: destination,
        ..Settings::default()
    })
    .await
    .unwrap();
    let record = sqlx::query("SELECT uuid,name FROM profiles")
        .fetch_one(restored.pool())
        .await
        .unwrap();
    assert_eq!(record.try_get::<String, _>(0).unwrap(), "profile");
    assert_eq!(record.try_get::<String, _>(1).unwrap(), "Alice");
    restored.pool().close().await;
    database.pool().close().await;
}

#[tokio::test]
async fn corrupt_skin_prevents_a_partial_backup() {
    let (directory, database) = database().await;
    write_key(&database);
    let hash = hex::encode(Sha256::digest(b"expected"));
    fs::create_dir(database.data_dir().join("textures")).unwrap();
    fs::write(database.data_dir().join("textures").join(&hash), b"wrong").unwrap();
    account(&database, "profile", Some(&hash)).await;
    let archive = directory.path().join("backup.tar.gz");
    assert!(maintenance::backup_data(&database, &archive).await.is_err());
    assert!(!archive.exists());
    database.pool().close().await;
}

#[tokio::test]
async fn restore_rejects_path_traversal_links_and_duplicate_entries() {
    for variant in ["../escaped", "link", "duplicate"] {
        let directory = tempfile::tempdir().unwrap();
        let archive = directory.path().join("unsafe.tar.gz");
        make_unsafe_archive(&archive, variant);
        let destination = directory.path().join("restored");
        assert!(
            maintenance::restore_data(&archive, &destination)
                .await
                .is_err()
        );
        assert!(!destination.exists());
        assert!(!directory.path().join("escaped").exists());
    }
}

fn make_unsafe_archive(path: &Path, variant: &str) {
    let output = fs::File::create(path).unwrap();
    let gzip = flate2::write::GzEncoder::new(output, flate2::Compression::default());
    let mut archive = tar::Builder::new(gzip);
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o600);
    if variant == "link" {
        header.set_path("nomi-auth.sqlite3").unwrap();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name("../escaped").unwrap();
        header.set_size(0);
        header.set_cksum();
        archive.append(&header, &[][..]).unwrap();
    } else {
        header.set_path("nomi-auth.sqlite3").unwrap();
        header.set_size(1);
        if variant == "../escaped" {
            let bytes = header.as_mut_bytes();
            bytes[..100].fill(0);
            bytes[..10].copy_from_slice(b"../escaped");
        }
        header.set_cksum();
        archive.append(&header, &b"x"[..]).unwrap();
        if variant == "duplicate" {
            archive.append(&header, &b"x"[..]).unwrap();
        }
    }
    archive.into_inner().unwrap().finish().unwrap();
}

fn mysql_settings(directory: &Path) -> Settings {
    let database_name =
        std::env::var("NOMI_TEST_MYSQL_DATABASE").expect("Set an isolated test database");
    assert!(
        database_name.starts_with("nomi_auth_test_"),
        "Refusing to modify a non-test database"
    );
    Settings {
        data_dir: directory.to_owned(),
        database_backend: "mysql".into(),
        mysql_database: database_name,
        mysql_user: std::env::var("NOMI_TEST_MYSQL_USER").unwrap(),
        mysql_password: std::env::var("NOMI_TEST_MYSQL_PASSWORD").unwrap(),
        mysql_host: std::env::var("NOMI_TEST_MYSQL_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
        mysql_port: std::env::var("NOMI_TEST_MYSQL_PORT")
            .unwrap_or_else(|_| "3306".into())
            .parse()
            .unwrap(),
        ..Settings::default()
    }
}

async fn clear_mysql(database: &Database) {
    let mut transaction = database.write().await.unwrap();
    for table in transfer::TABLES
        .iter()
        .rev()
        .filter(|table| **table != "schema_versions")
    {
        sqlx::query(&format!("DELETE FROM {table}"))
            .execute(transaction.connection())
            .await
            .unwrap();
    }
    transaction.commit().await.unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated NOMI_TEST_MYSQL_* database; run with --ignored --test-threads=1"]
async fn mariadb_migration_roundtrip_and_cancelled_writer_release() {
    let (directory, source) = database().await;
    write_key(&source);
    account(&source, "profile", None).await;
    let source_path = source.data_dir().join("nomi-auth.sqlite3");
    source.pool().close().await;
    let before = fs::read(&source_path).unwrap();

    let settings = mysql_settings(&directory.path().join("mysql"));
    let target = Database::open(&settings).await.unwrap();
    clear_mysql(&target).await;
    let counts = transfer::import_sqlite(&source_path, &target)
        .await
        .unwrap();
    assert_eq!(counts["accounts"], 1);
    assert_eq!(fs::read(&source_path).unwrap(), before);
    assert!(
        transfer::import_sqlite(&source_path, &target)
            .await
            .is_err()
    );

    fs::copy(
        source.data_dir().join("texture-signing.pem"),
        target.data_dir().join("texture-signing.pem"),
    )
    .unwrap();
    let archive = directory.path().join("mysql.tar.gz");
    maintenance::backup_data(&target, &archive).await.unwrap();
    maintenance::restore_data(&archive, &directory.path().join("mysql-restored"))
        .await
        .unwrap();

    let other = Database::open(&settings).await.unwrap();
    let first = target.write().await.unwrap();
    let second_database = other.clone();
    let waiting = tokio::spawn(async move {
        second_database
            .write()
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!waiting.is_finished());
    drop(first);
    tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .unwrap()
        .unwrap();
    clear_mysql(&target).await;
    other.pool().close().await;
    target.pool().close().await;
}

#[tokio::test]
#[ignore = "requires an isolated NOMI_TEST_MYSQL_* database; run with --ignored --test-threads=1"]
async fn mariadb_failed_import_rolls_back_previous_tables() {
    let (directory, source) = database().await;
    account(&source, &"z".repeat(65), None).await;
    source.pool().close().await;
    let target = Database::open(&mysql_settings(&directory.path().join("mysql")))
        .await
        .unwrap();
    clear_mysql(&target).await;
    assert!(
        transfer::import_sqlite(&source.data_dir().join("nomi-auth.sqlite3"), &target)
            .await
            .is_err()
    );
    assert_eq!(count(&target, "accounts").await, 0);
    assert_eq!(count(&target, "profiles").await, 0);
    target.pool().close().await;
}
