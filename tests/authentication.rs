use std::sync::Arc;

use nomi_auth_neo::{
    core::{Reply, Request, Settings},
    services::Auth,
    storage::Database,
};
use serde_json::{Value, json};
use tempfile::TempDir;

async fn service() -> (TempDir, Auth) {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings {
        data_dir: directory.path().to_owned(),
        bot_token: "x".repeat(32),
        bot_app_id: "app".into(),
        group_openid: "group".into(),
        ..Settings::default()
    };
    let database = Database::open(&settings).await.unwrap();
    (directory, Auth::new(Arc::new(settings), database))
}

fn request(method: &str, path: &str, body: Value) -> Request {
    Request {
        method: method.into(),
        path: path.into(),
        body,
        ..Request::default()
    }
}

fn authorized(method: &str, path: &str, token: &str, body: Value) -> Request {
    let mut request = request(method, path, body);
    request.authorization = Some(format!("Bearer {token}"));
    request
}

fn event(value: &str, member: &str, event: &str, registration: bool) -> Value {
    let mut fields =
        json!({"bot_app_id":"app","group_openid":"group","member_openid":member,"event_id":event});
    fields[if registration { "name" } else { "code" }] = json!(value);
    fields
}

async fn call(auth: &Auth, request: Request) -> Value {
    auth.handle(&request).await.unwrap().body.unwrap()
}

fn body(reply: Reply) -> Value {
    reply.body.unwrap()
}

async fn begin(auth: &Auth) -> Value {
    call(auth, request("POST", "/api/v1/logins", json!({}))).await
}

async fn claim(auth: &Auth, login: &Value, member: &str, event_id: &str) -> Value {
    call(
        auth,
        authorized(
            "POST",
            "/internal/v1/logins/verify",
            &"x".repeat(32),
            event(login["code"].as_str().unwrap(), member, event_id, false),
        ),
    )
    .await
}

async fn register(auth: &Auth, name: &str, member: &str, event_id: &str) -> Value {
    call(
        auth,
        authorized(
            "POST",
            "/internal/v1/logins/register",
            &"x".repeat(32),
            event(name, member, event_id, true),
        ),
    )
    .await
}

async fn exchange(auth: &Auth, login: &Value, retry_id: Option<&str>) -> Value {
    let path = format!(
        "/api/v1/logins/{}/session",
        login["request_id"].as_str().unwrap()
    );
    let mut request = authorized(
        "POST",
        &path,
        login["poll_token"].as_str().unwrap(),
        json!({}),
    );
    request.request_id = retry_id.map(str::to_owned);
    call(auth, request).await
}

#[tokio::test]
async fn group_login_rename_refresh_and_revocation_preserve_identity() {
    let (_directory, auth) = service().await;
    let login = begin(&auth).await;
    assert_eq!(
        claim(&auth, &login, "member", "claim").await["status"],
        "AWAITING_NAME"
    );
    let created = register(&auth, "Alice", "member", "register").await;
    let session = exchange(&auth, &login, Some(&"a".repeat(64))).await;
    assert_eq!(
        session,
        exchange(&auth, &login, Some(&"a".repeat(64))).await
    );
    assert_eq!(created["uuid"], session["game"]["selectedProfile"]["id"]);
    assert_eq!(
        session["refresh_expires_at"].as_i64().unwrap()
            - session["game_expires_at"].as_i64().unwrap(),
        29 * 86400
    );

    let renamed = call(
        &auth,
        authorized(
            "POST",
            "/internal/v1/profiles/rename",
            &"x".repeat(32),
            event("NewAlice", "member", "rename", true),
        ),
    )
    .await;
    assert_eq!(renamed["uuid"], created["uuid"]);
    let profile = call(
        &auth,
        authorized(
            "GET",
            "/api/v1/game/profile",
            session["game"]["accessToken"].as_str().unwrap(),
            json!({}),
        ),
    )
    .await;
    assert_eq!(profile, json!({"id":created["uuid"],"name":"NewAlice"}));

    let mut refresh = authorized(
        "POST",
        "/api/v1/sessions/refresh",
        session["refresh_token"].as_str().unwrap(),
        json!({}),
    );
    refresh.request_id = Some("b".repeat(64));
    let renewed = call(&auth, refresh.clone()).await;
    assert_eq!(renewed, call(&auth, refresh).await);
    let revoked = auth
        .handle(&authorized(
            "DELETE",
            "/api/v1/sessions/refresh",
            renewed["refresh_token"].as_str().unwrap(),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(revoked.status, 204);
    let invalid = auth
        .handle(&authorized(
            "GET",
            "/api/v1/game/profile",
            renewed["game"]["accessToken"].as_str().unwrap(),
            json!({}),
        ))
        .await
        .err()
        .unwrap();
    assert_eq!(invalid.code, "INVALID_TOKEN");
}

#[tokio::test]
async fn one_code_has_one_claimant_and_one_conflicting_event_payload() {
    let (_directory, auth) = service().await;
    let login = begin(&auth).await;
    let first = authorized(
        "POST",
        "/internal/v1/logins/verify",
        &"x".repeat(32),
        event(login["code"].as_str().unwrap(), "one", "first", false),
    );
    let second = authorized(
        "POST",
        "/internal/v1/logins/verify",
        &"x".repeat(32),
        event(login["code"].as_str().unwrap(), "two", "second", false),
    );
    let (one, two) = tokio::join!(auth.handle(&first), auth.handle(&second));
    assert_eq!(usize::from(one.is_ok()) + usize::from(two.is_ok()), 1);
    let rejected = if one.is_err() {
        one.err().unwrap()
    } else {
        two.err().unwrap()
    };
    assert_eq!(rejected.code, "CODE_USED");
    let winner = if first.body["member_openid"] == "one" && auth.handle(&first).await.is_ok() {
        &first
    } else {
        &second
    };
    let original = call(&auth, winner.clone()).await;
    assert_eq!(original["status"], "AWAITING_NAME");
    let mut changed = winner.clone();
    changed.body["member_openid"] = json!("someone_else");
    assert_eq!(
        auth.handle(&changed).await.err().unwrap().code,
        "EVENT_CONFLICT"
    );
}

#[tokio::test]
async fn conflict_is_saved_and_private_poll_consumes_failure() {
    let (_directory, auth) = service().await;
    let first = begin(&auth).await;
    claim(&auth, &first, "first", "claim-one").await;
    register(&auth, "Alice", "first", "register-one").await;
    let second = begin(&auth).await;
    claim(&auth, &second, "second", "claim-two").await;
    let failed = register(&auth, "alice", "second", "register-two").await;
    assert_eq!(failed, json!({"status":"FAILED","code":"NAME_TAKEN"}));
    assert_eq!(
        failed,
        register(&auth, "alice", "second", "register-two").await
    );
    let path = format!("/api/v1/logins/{}", second["request_id"].as_str().unwrap());
    let poll = authorized(
        "GET",
        &path,
        second["poll_token"].as_str().unwrap(),
        json!({}),
    );
    assert_eq!(call(&auth, poll.clone()).await["error"], "NAME_TAKEN");
    assert_eq!(auth.handle(&poll).await.err().unwrap().status, 404);
}

#[tokio::test]
async fn legacy_registration_and_private_poll_remain_supported() {
    let (_directory, auth) = service().await;
    let registration = call(
        &auth,
        request("POST", "/api/v1/registrations", json!({"name":"Alice"})),
    )
    .await;
    let redeemed = call(
        &auth,
        authorized(
            "POST",
            "/internal/v1/registrations/redeem",
            &"x".repeat(32),
            event(
                registration["code"].as_str().unwrap(),
                "member",
                "event",
                false,
            ),
        ),
    )
    .await;
    assert_eq!(redeemed["status"], "COMPLETED");
    let path = format!(
        "/api/v1/registrations/{}/session",
        registration["request_id"].as_str().unwrap()
    );
    let exchange = authorized(
        "POST",
        &path,
        registration["poll_token"].as_str().unwrap(),
        json!({}),
    );
    let response = body(auth.handle(&exchange).await.unwrap());
    assert_eq!(response["game"]["selectedProfile"]["name"], "Alice");
    assert_eq!(auth.handle(&exchange).await.err().unwrap().status, 404);
}

#[tokio::test]
async fn invalid_names_and_wrong_group_do_not_claim_requests() {
    let (_directory, auth) = service().await;
    assert_eq!(
        auth.handle(&request(
            "POST",
            "/api/v1/registrations",
            json!({"name":"ab"})
        ))
        .await
        .err()
        .unwrap()
        .status,
        422
    );
    assert_eq!(
        auth.handle(&request("POST", "/api/v1/logins", json!({"name":"Alice"})))
            .await
            .err()
            .unwrap()
            .status,
        422
    );
    let login = begin(&auth).await;
    let mut wrong = event(login["code"].as_str().unwrap(), "member", "wrong", false);
    wrong["group_openid"] = json!("other");
    let error = auth
        .handle(&authorized(
            "POST",
            "/internal/v1/logins/verify",
            &"x".repeat(32),
            wrong,
        ))
        .await
        .err()
        .unwrap();
    assert_eq!(error.code, "WRONG_GROUP");
    assert_eq!(
        claim(&auth, &login, "member", "right").await["status"],
        "AWAITING_NAME"
    );
}

async fn existing_account() -> (TempDir, Auth, Arc<Database>) {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings {
        data_dir: directory.path().to_owned(),
        bot_token: "x".repeat(32),
        bot_app_id: "app".into(),
        group_openid: "group".into(),
        ..Settings::default()
    };
    let database = Database::open(&settings).await.unwrap();
    let mut transaction = database.write().await.unwrap();
    sqlx::query("INSERT INTO accounts VALUES('account','Original','original','active',1)")
        .execute(transaction.connection())
        .await
        .unwrap();
    sqlx::query("INSERT INTO profiles(uuid,account_id,name,name_normalized) VALUES('12345678901234567890123456789012','account','Before','before')")
        .execute(transaction.connection()).await.unwrap();
    transaction.commit().await.unwrap();
    (
        directory,
        Auth::new(Arc::new(settings), database.clone()),
        database,
    )
}

#[tokio::test]
async fn existing_python_receipt_replays_without_a_live_request() {
    use nomi_auth_neo::core::security::{digest, now};

    let (_directory, auth, database) = existing_account().await;
    let canonical = r#"{"code":"OLD-CODE","bot_app_id":"app","group_openid":"group","member_openid":"member","event_id":"old-event"}"#;
    let original_result =
        r#"{"status": "VERIFIED", "name": "Before", "uuid": "12345678901234567890123456789012"}"#;
    let mut transaction = database.write().await.unwrap();
    sqlx::query("INSERT INTO receipts VALUES(?,?,?,?,?,?)")
        .bind("app")
        .bind("old-event")
        .bind("login")
        .bind(digest(canonical))
        .bind(original_result)
        .bind(now())
        .execute(transaction.connection())
        .await
        .unwrap();
    transaction.commit().await.unwrap();

    let request = authorized(
        "POST",
        "/internal/v1/logins/verify",
        &"x".repeat(32),
        event("OLD-CODE", "member", "old-event", false),
    );
    let replayed = call(&auth, request).await;
    assert_eq!(
        replayed,
        serde_json::from_str::<Value>(original_result).unwrap()
    );
}

#[tokio::test]
async fn existing_retry_credentials_keep_their_values_and_expirations() {
    use nomi_auth_neo::core::security::{derive_token, digest, now};

    let (_directory, auth, database) = existing_account().await;
    let request_id = "a".repeat(64);
    let seed = "old-refresh-token";
    let nonce = "python-generated-nonce";
    let game = derive_token(seed, &request_id, nonce, "game");
    let refresh = derive_token(seed, &request_id, nonce, "refresh");
    let game_expiry = now() + 3000;
    let refresh_expiry = now() + 6000;
    let mut transaction = database.write().await.unwrap();
    for (token, kind, expiry) in [
        (&game, "game", game_expiry),
        (&refresh, "refresh", refresh_expiry),
    ] {
        sqlx::query("INSERT INTO tokens VALUES(?,?,?,?,?)")
            .bind(digest(token))
            .bind("account")
            .bind(kind)
            .bind("existing-client")
            .bind(expiry)
            .execute(transaction.connection())
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO refresh_retries VALUES(?,?,?,?,?,?)")
        .bind(digest(seed))
        .bind(digest(&request_id))
        .bind(nonce)
        .bind(digest(&game))
        .bind(digest(&refresh))
        .bind(now() + 120)
        .execute(transaction.connection())
        .await
        .unwrap();
    transaction.commit().await.unwrap();

    let mut request = authorized("POST", "/api/v1/sessions/refresh", seed, json!({}));
    request.request_id = Some(request_id);
    let result = call(&auth, request).await;
    assert_eq!(result["game"]["accessToken"], game);
    assert_eq!(result["refresh_token"], refresh);
    assert_eq!(result["game_expires_at"], game_expiry);
    assert_eq!(result["refresh_expires_at"], refresh_expiry);
    assert_eq!(
        result["game"]["selectedProfile"]["id"],
        "12345678901234567890123456789012"
    );
}
