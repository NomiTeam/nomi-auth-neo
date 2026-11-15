use std::sync::Arc;

use nomi_auth_neo::{
    core::{Request, Settings, security::now},
    services::Auth,
    storage::Database,
};
use serde_json::{Value, json};
use sqlx::Row;

async fn service() -> (tempfile::TempDir, Auth, Arc<Database>) {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings {
        data_dir: directory.path().to_owned(),
        bot_token: "x".repeat(32),
        bot_app_id: "app".into(),
        group_openid: "group".into(),
        ..Settings::default()
    };
    let database = Database::open(&settings).await.unwrap();
    let auth = Auth::new(Arc::new(settings), database.clone());
    (directory, auth, database)
}

fn request(method: &str, path: &str, token: Option<&str>, body: Value) -> Request {
    Request {
        method: method.into(),
        path: path.into(),
        body,
        authorization: token.map(|value| format!("Bearer {value}")),
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

async fn count(database: &Database, table: &str) -> i64 {
    sqlx::query(&format!("SELECT COUNT(*) FROM {table}"))
        .fetch_one(database.pool())
        .await
        .unwrap()
        .try_get(0)
        .unwrap()
}

async fn clear_test_database(database: &Database) {
    let mut transaction = database.write().await.unwrap();
    for table in nomi_auth_neo::storage::transfer::TABLES.iter().rev() {
        if *table != "schema_versions" {
            sqlx::query(&format!("DELETE FROM {table}"))
                .execute(transaction.connection())
                .await
                .unwrap();
        }
    }
    transaction.commit().await.unwrap();
}

async fn exercise_login(auth: &Auth, database: &Database) {
    let login = begin(auth).await;
    let profile = auth
        .test_login(login["code"].as_str().unwrap(), "LocalTest")
        .await
        .unwrap();
    assert_eq!(count(database, "accounts").await, 1);
    assert_eq!(count(database, "identities").await, 0);
    let path = format!(
        "/api/v1/logins/{}/session",
        login["request_id"].as_str().unwrap()
    );
    let session = auth
        .handle(&request(
            "POST",
            &path,
            login["poll_token"].as_str(),
            json!({}),
        ))
        .await
        .unwrap()
        .body
        .unwrap();
    assert_eq!(session["game"]["selectedProfile"]["id"], profile.uuid);
    assert_eq!(session["game"]["selectedProfile"]["name"], "LocalTest");

    let next = begin(auth).await;
    let reused = auth
        .test_login(next["code"].as_str().unwrap(), "localtest")
        .await
        .unwrap();
    assert_eq!(reused.uuid, profile.uuid);
    assert_eq!(count(database, "accounts").await, 1);
    let created: i64 =
        sqlx::query("SELECT COUNT(*) FROM audit WHERE action='test_account_created'")
            .fetch_one(database.pool())
            .await
            .unwrap()
            .try_get(0)
            .unwrap();
    assert_eq!(created, 1);
}

#[tokio::test]
async fn local_test_login_uses_existing_launcher_flow_and_preserves_uuid() {
    let (_directory, auth, database) = service().await;
    exercise_login(&auth, &database).await;
}

#[tokio::test]
async fn invalid_expired_cancelled_and_claimed_codes_create_no_accounts() {
    let (_directory, auth, database) = service().await;
    assert!(auth.test_login("missing", "ValidTest").await.is_err());
    let invalid = begin(&auth).await;
    assert!(
        auth.test_login(invalid["code"].as_str().unwrap(), "bad name")
            .await
            .is_err()
    );
    for status in ["PENDING", "AWAITING_NAME", "VERIFIED", "FAILED"] {
        let login = begin(&auth).await;
        sqlx::query("UPDATE login_requests SET status=?,expires_at=? WHERE id=?")
            .bind(status)
            .bind(if status == "PENDING" {
                now() - 1
            } else {
                now() + 300
            })
            .bind(login["request_id"].as_str().unwrap())
            .execute(database.pool())
            .await
            .unwrap();
        assert!(
            auth.test_login(login["code"].as_str().unwrap(), "NeverCreated")
                .await
                .is_err()
        );
    }
    let cancelled = begin(&auth).await;
    let path = format!(
        "/api/v1/logins/{}",
        cancelled["request_id"].as_str().unwrap()
    );
    auth.handle(&request(
        "DELETE",
        &path,
        cancelled["poll_token"].as_str(),
        json!({}),
    ))
    .await
    .unwrap();
    assert!(
        auth.test_login(cancelled["code"].as_str().unwrap(), "NeverCreated")
            .await
            .is_err()
    );
    assert_eq!(count(&database, "accounts").await, 0);
    assert_eq!(count(&database, "audit").await, 0);
}

#[tokio::test]
async fn qq_accounts_and_disabled_test_accounts_cannot_be_approved() {
    let (_directory, auth, database) = service().await;
    let first = begin(&auth).await;
    let profile = auth
        .test_login(first["code"].as_str().unwrap(), "Reserved")
        .await
        .unwrap();
    sqlx::query("INSERT INTO identities VALUES(?,?,?,?)")
        .bind(&profile.account_id)
        .bind("app")
        .bind("group")
        .bind("member")
        .execute(database.pool())
        .await
        .unwrap();
    let login = begin(&auth).await;
    assert_eq!(
        auth.test_login(login["code"].as_str().unwrap(), "RESERVED")
            .await
            .err()
            .unwrap()
            .code,
        "ACCOUNT_BOUND"
    );
    sqlx::query("DELETE FROM identities")
        .execute(database.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE accounts SET status='disabled'")
        .execute(database.pool())
        .await
        .unwrap();
    assert_eq!(
        auth.test_login(login["code"].as_str().unwrap(), "Reserved")
            .await
            .err()
            .unwrap()
            .code,
        "ACCOUNT_UNAVAILABLE"
    );
    let status = auth
        .handle(&request(
            "GET",
            &format!("/api/v1/logins/{}", login["request_id"].as_str().unwrap()),
            login["poll_token"].as_str(),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(status.body.unwrap()["status"], "PENDING");
}

#[tokio::test]
async fn concurrent_admin_approvals_cannot_reassign_one_code() {
    let (_directory, auth, database) = service().await;
    let login = begin(&auth).await;
    let code = login["code"].as_str().unwrap();
    let (first, second) = tokio::join!(
        auth.test_login(code, "FirstTest"),
        auth.test_login(code, "SecondTest")
    );
    assert_ne!(first.is_ok(), second.is_ok());
    assert_eq!(count(&database, "accounts").await, 1);
}

#[tokio::test]
#[ignore = "requires an isolated NOMI_TEST_MYSQL_* database; run with --ignored --test-threads=1"]
async fn mysql_test_login_roundtrip() {
    let directory = tempfile::tempdir().unwrap();
    let database_name = std::env::var("NOMI_TEST_MYSQL_DATABASE").unwrap();
    assert!(database_name.starts_with("nomi_auth_test_"));
    let settings = Settings {
        data_dir: directory.path().to_owned(),
        database_backend: "mysql".into(),
        mysql_database: database_name,
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
    clear_test_database(&database).await;
    let auth = Auth::new(Arc::new(settings), database.clone());
    exercise_login(&auth, &database).await;
    clear_test_database(&database).await;
    database.pool().close().await;
}
