use std::sync::Arc;

use nomi_auth_neo::{
    core::{
        Request, Settings,
        security::{digest, now},
    },
    services::{Admin, Auth, Profile},
    storage::{Database, transfer},
};
use serde_json::{Value, json};
use sqlx::{Executor, Row};

fn request(method: &str, path: &str, token: Option<&str>, body: Value) -> Request {
    Request {
        method: method.into(),
        path: path.into(),
        authorization: token.map(|s| format!("Bearer {s}")),
        body,
        ..Request::default()
    }
}

async fn begin(auth: &Auth) -> Value {
    auth.handle(&request("POST", "/api/v1/logins", None, json!({})))
        .await
        .unwrap()
        .body
        .unwrap()
}

async fn create(auth: &Auth, name: &str) -> (Profile, Value) {
    let login = begin(auth).await;
    let profile = auth
        .login(login["code"].as_str().unwrap(), name)
        .await
        .unwrap();
    let mut claim = request(
        "POST",
        &format!(
            "/api/v1/logins/{}/session",
            login["request_id"].as_str().unwrap()
        ),
        login["poll_token"].as_str(),
        json!({}),
    );
    claim.request_id = Some(digest(name));
    let session = auth.handle(&claim).await.unwrap().body.unwrap();
    (profile, session)
}

struct Fixture {
    target: Profile,
    other: Profile,
    session: Value,
    other_session: Value,
    pending: Value,
    texture: std::path::PathBuf,
}

async fn seed(auth: &Auth, database: &Database) -> Fixture {
    let (target, session) = create(auth, "DeleteMe").await;
    let (other, other_session) = create(auth, "KeepMe").await;
    sqlx::query("INSERT INTO identities VALUES(?,'app','group','member')")
        .bind(&target.account_id)
        .execute(database.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO joins VALUES(?,'server-check',?)")
        .bind(&target.uuid)
        .bind(now() + 300)
        .execute(database.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO refresh_retries VALUES('old-refresh','retry','nonce',?,?,?)")
        .bind(digest(session["game"]["accessToken"].as_str().unwrap()))
        .bind(digest(session["refresh_token"].as_str().unwrap()))
        .bind(now() + 120)
        .execute(database.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO registrations(id,code_hash,poll_hash,name,expires_at,account_id) VALUES('legacy','legacy-code','legacy-poll','DeleteMe',?,?)")
        .bind(now()+300).bind(&target.account_id).execute(database.pool()).await.unwrap();
    let claimed = begin(auth).await;
    sqlx::query("UPDATE login_requests SET status='AWAITING_NAME',app_id='app',group_id='group',member_id='member' WHERE id=?")
        .bind(claimed["request_id"].as_str().unwrap()).execute(database.pool()).await.unwrap();
    let pending = begin(auth).await;

    for (event, result) in [
        ("target", json!({"status":"VERIFIED","uuid":target.uuid})),
        (
            "other",
            json!({"status":"VERIFIED","uuid":other.uuid,"note":target.uuid}),
        ),
    ] {
        sqlx::query("INSERT INTO receipts(app_id,event_id,operation,payload_hash,result,created_at) VALUES('app',?,'login','hash',?,?)")
            .bind(event).bind(result.to_string()).bind(now()).execute(database.pool()).await.unwrap();
    }

    let hash = "a".repeat(64);
    let directory = database.data_dir().join("textures");
    std::fs::create_dir_all(&directory).unwrap();
    let texture = directory.join(&hash);
    std::fs::write(&texture, b"shared texture contents").unwrap();
    sqlx::query("UPDATE profiles SET skin_hash=?")
        .bind(&hash)
        .execute(database.pool())
        .await
        .unwrap();
    Fixture {
        target,
        other,
        session,
        other_session,
        pending,
        texture,
    }
}

async fn count(database: &Database, table: &str) -> i64 {
    sqlx::query(&format!("SELECT COUNT(*) FROM {table}"))
        .fetch_one(database.pool())
        .await
        .unwrap()
        .try_get(0)
        .unwrap()
}

async fn exercise_delete(auth: &Auth, database: &Arc<Database>) {
    let fixture = seed(auth, database).await;
    let admin = Admin::new(database.clone());
    let mut before = Vec::new();
    for table in transfer::TABLES {
        before.push(count(database, table).await);
    }
    let error = admin.delete("deleteme").await.unwrap_err();
    assert_eq!(error.code, "ACCOUNT_ENABLED");
    for (table, expected) in transfer::TABLES.iter().zip(before) {
        assert_eq!(count(database, table).await, expected);
    }
    let current = request(
        "GET",
        "/api/v1/game/profile",
        fixture.session["game"]["accessToken"].as_str(),
        json!({}),
    );
    assert!(auth.handle(&current).await.is_ok());
    Admin::new(database.clone())
        .set_enabled("DeleteMe", false)
        .await
        .unwrap();
    assert_eq!(
        Admin::new(database.clone())
            .delete("deleteme")
            .await
            .unwrap(),
        "DeleteMe"
    );
    for table in ["accounts", "profiles", "receipts", "login_requests"] {
        assert_eq!(
            count(database, table).await,
            1,
            "Unexpected remaining {table}"
        );
    }
    for table in ["identities", "registrations", "joins", "refresh_retries"] {
        assert_eq!(
            count(database, table).await,
            0,
            "Target retained in {table}"
        );
    }
    assert_eq!(count(database, "tokens").await, 3);
    assert_eq!(count(database, "login_retries").await, 1);
    let audit: i64 = sqlx::query("SELECT COUNT(*) FROM audit WHERE account_id=?")
        .bind(&fixture.target.account_id)
        .fetch_one(database.pool())
        .await
        .unwrap()
        .try_get(0)
        .unwrap();
    assert_eq!(audit, 0);
    assert_eq!(
        std::fs::read(&fixture.texture).unwrap(),
        b"shared texture contents"
    );
    let old = request(
        "GET",
        "/api/v1/game/profile",
        fixture.session["game"]["accessToken"].as_str(),
        json!({}),
    );
    assert!(auth.handle(&old).await.is_err());
    let other = request(
        "GET",
        "/api/v1/game/profile",
        fixture.other_session["game"]["accessToken"].as_str(),
        json!({}),
    );
    assert_eq!(
        auth.handle(&other).await.unwrap().body.unwrap()["id"],
        fixture.other.uuid
    );
    assert!(
        auth.handle(&request(
            "GET",
            &format!(
                "/api/v1/logins/{}",
                fixture.pending["request_id"].as_str().unwrap()
            ),
            fixture.pending["poll_token"].as_str(),
            json!({})
        ))
        .await
        .is_ok()
    );

    let login = begin(auth).await;
    let recreated = auth
        .login(login["code"].as_str().unwrap(), "DeleteMe")
        .await
        .unwrap();
    assert_ne!(recreated.uuid, fixture.target.uuid);
}

#[tokio::test]
async fn deletion_cleans_bound_accounts_but_preserves_other_accounts_and_shared_skins() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings {
        data_dir: directory.path().to_owned(),
        ..Settings::default()
    };
    let database = Database::open(&settings).await.unwrap();
    let auth = Auth::new(Arc::new(settings), database.clone());
    exercise_delete(&auth, &database).await;
}

async fn exercise_rollback(auth: &Auth, database: &Arc<Database>) {
    let fixture = seed(auth, database).await;
    Admin::new(database.clone())
        .set_enabled("DeleteMe", false)
        .await
        .unwrap();
    let mut before = Vec::new();
    for table in transfer::TABLES {
        before.push(count(database, table).await);
    }
    assert!(
        Admin::new(database.clone())
            .delete("NoSuchAccount")
            .await
            .is_err()
    );
    let trigger = if database.is_mysql() {
        "CREATE TRIGGER block_delete BEFORE DELETE ON accounts FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='injected failure'"
    } else {
        "CREATE TRIGGER block_delete BEFORE DELETE ON accounts BEGIN SELECT RAISE(ABORT, 'injected failure'); END"
    };
    database.pool().execute(trigger).await.unwrap();
    assert!(
        Admin::new(database.clone())
            .delete("DeleteMe")
            .await
            .is_err()
    );
    for (table, expected) in transfer::TABLES.iter().zip(before) {
        assert_eq!(
            count(database, table).await,
            expected,
            "Deletion partially changed {table}"
        );
    }
    assert!(fixture.texture.exists());
    sqlx::query("DROP TRIGGER block_delete")
        .execute(database.pool())
        .await
        .unwrap();
    Admin::new(database.clone())
        .set_enabled("DeleteMe", false)
        .await
        .unwrap();
    Admin::new(database.clone())
        .delete("DeleteMe")
        .await
        .unwrap();
    assert_eq!(count(database, "accounts").await, 1);
}

#[tokio::test]
async fn failed_deletion_rolls_back_children_and_missing_accounts_do_not_change_data() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings {
        data_dir: directory.path().to_owned(),
        ..Settings::default()
    };
    let database = Database::open(&settings).await.unwrap();
    let auth = Auth::new(Arc::new(settings), database.clone());
    exercise_rollback(&auth, &database).await;
}

#[tokio::test]
async fn concurrent_enable_and_delete_never_delete_an_active_account() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings {
        data_dir: directory.path().to_owned(),
        ..Settings::default()
    };
    let database = Database::open(&settings).await.unwrap();
    // Separate handles model the running service and an independent CLI process.
    let other = Database::open(&settings).await.unwrap();
    let auth = Auth::new(Arc::new(settings), database.clone());
    let (profile, _) = create(&auth, "RaceDelete").await;
    let admin = Admin::new(database.clone());
    admin.set_enabled("RaceDelete", false).await.unwrap();
    let second = Admin::new(other);
    let (enabled, deleted) = tokio::join!(
        admin.set_enabled("RaceDelete", true),
        second.delete("RaceDelete")
    );
    assert_ne!(enabled.is_ok(), deleted.is_ok());
    let status: Option<String> = sqlx::query_scalar("SELECT status FROM accounts WHERE id=?")
        .bind(&profile.account_id)
        .fetch_optional(database.pool())
        .await
        .unwrap();
    if enabled.is_ok() {
        assert_eq!(deleted.unwrap_err().code, "ACCOUNT_ENABLED");
        assert_eq!(status.as_deref(), Some("active"));
    } else {
        assert_eq!(enabled.unwrap_err().code, "ACCOUNT_NOT_FOUND");
        assert!(status.is_none());
    }
}

async fn clear_test_database(database: &Database) {
    let mut transaction = database.write().await.unwrap();
    for table in transfer::TABLES.iter().rev() {
        if *table != "schema_versions" {
            sqlx::query(&format!("DELETE FROM {table}"))
                .execute(transaction.connection())
                .await
                .unwrap();
        }
    }
    transaction.commit().await.unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated NOMI_TEST_MYSQL_* database; run with --ignored --test-threads=1"]
async fn mysql_account_deletion_and_failure_rollback() {
    let directory = tempfile::tempdir().unwrap();
    let name = std::env::var("NOMI_TEST_MYSQL_DATABASE").unwrap();
    assert!(name.starts_with("nomi_auth_test_"));
    let settings = Settings {
        data_dir: directory.path().to_owned(),
        database_backend: "mysql".into(),
        mysql_database: name,
        mysql_host: std::env::var("NOMI_TEST_MYSQL_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
        mysql_port: std::env::var("NOMI_TEST_MYSQL_PORT")
            .unwrap_or_else(|_| "3306".into())
            .parse()
            .unwrap(),
        mysql_user: std::env::var("NOMI_TEST_MYSQL_USER").unwrap(),
        mysql_password: std::env::var("NOMI_TEST_MYSQL_PASSWORD").unwrap(),
        ..Settings::default()
    };
    let database = Database::open(&settings).await.unwrap();
    let auth = Auth::new(Arc::new(settings), database.clone());
    clear_test_database(&database).await;
    exercise_delete(&auth, &database).await;
    clear_test_database(&database).await;
    exercise_rollback(&auth, &database).await;
    clear_test_database(&database).await;
    database.pool().close().await;
}
