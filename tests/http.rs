use std::{io::Cursor, sync::Arc};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderValue, Request as HttpRequest, StatusCode, header},
    response::Response,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use image::ImageFormat;
use nomi_auth_neo::{
    core::{
        Settings,
        security::{digest, now},
    },
    http::App,
};
use rsa::{Pkcs1v15Sign, RsaPublicKey, pkcs8::DecodePublicKey};
use serde_json::{Value, json};
use sha1::{Digest, Sha1};
use tower::ServiceExt;

const SEEDED_PROFILE: &str = "12345678901234567890123456789012";

#[tokio::test]
async fn internal_mtls_attestation_is_local_exact_and_fail_closed() {
    let fixture = Fixture::with_mtls(true).await;
    for path in [
        "/internal/v1/logins/verify",
        "/%69nternal/v1/logins/verify",
        "/internal/v1/logins/verify/",
    ] {
        for (peer, verification) in [
            (None, Some("SUCCESS")),
            (Some("192.0.2.1:1"), Some("SUCCESS")),
            (Some("127.0.0.1:1"), None),
            (Some("127.0.0.1:1"), Some("success")),
            (Some("[::1]:1"), Some("FAILED")),
        ] {
            let mut attempt = authorized(json_request("POST", path, json!({})), &"x".repeat(32));
            if let Some(peer) = peer {
                attempt.extensions_mut().insert(axum::extract::ConnectInfo(
                    peer.parse::<std::net::SocketAddr>().unwrap(),
                ));
            }
            if let Some(verification) = verification {
                attempt.headers_mut().insert(
                    "x-nomi-client-verify",
                    HeaderValue::from_str(verification).unwrap(),
                );
            }
            let (status, body) = fixture.json(attempt).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(body["code"], "MTLS_REQUIRED");
        }
    }
    assert_eq!(
        fixture
            .json(request("GET", "/health", Body::empty()))
            .await
            .0,
        StatusCode::OK
    );
    let (status, login) = fixture
        .json(json_request("POST", "/api/v1/logins", json!({})))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let mut verified = authorized(
        json_request(
            "POST",
            "/internal/v1/logins/verify",
            event(login["code"].as_str().unwrap(), "mtls", false),
        ),
        &"x".repeat(32),
    );
    verified.extensions_mut().insert(axum::extract::ConnectInfo(
        "[::1]:1".parse::<std::net::SocketAddr>().unwrap(),
    ));
    verified
        .headers_mut()
        .insert("x-nomi-client-verify", HeaderValue::from_static("SUCCESS"));
    let (status, result) = fixture.json(verified).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result["status"], "AWAITING_NAME");
    for duplicate in [false, true] {
        let mut attempt = json_request(
            "POST",
            "/internal/v1/logins/verify",
            event("unknown-code", "certificate-only", false),
        );
        attempt.extensions_mut().insert(axum::extract::ConnectInfo(
            "127.0.0.1:1".parse::<std::net::SocketAddr>().unwrap(),
        ));
        attempt
            .headers_mut()
            .insert("x-nomi-client-verify", HeaderValue::from_static("SUCCESS"));
        if duplicate {
            attempt
                .headers_mut()
                .append("x-nomi-client-verify", HeaderValue::from_static("SUCCESS"));
        }
        let (status, body) = fixture.json(attempt).await;
        assert_eq!(
            status,
            if duplicate {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::UNAUTHORIZED
            }
        );
        assert_eq!(
            body["code"],
            if duplicate {
                "MTLS_REQUIRED"
            } else {
                "UNAUTHORIZED"
            }
        );
    }
    fixture.close().await;

    let legacy = Fixture::new().await;
    let (status, body) = legacy
        .json(authorized(
            json_request("POST", "/internal/v1/logins/verify", json!({})),
            &"x".repeat(32),
        ))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_ne!(body["code"], "MTLS_REQUIRED");
    legacy.close().await;
}

#[tokio::test]
async fn rate_limits_ignore_forwarded_addresses_from_untrusted_peers() {
    let fixture = Fixture::new().await;
    for sequence in 0..21 {
        let mut attempt = json_request("POST", "/api/v1/logins", json!({}));
        attempt.extensions_mut().insert(axum::extract::ConnectInfo(
            "192.0.2.1:1234".parse::<std::net::SocketAddr>().unwrap(),
        ));
        attempt.headers_mut().insert(
            "x-forwarded-for",
            HeaderValue::from_str(&format!("198.51.100.{sequence}")).unwrap(),
        );
        let (status, _) = fixture.json(attempt).await;
        assert_eq!(
            status,
            if sequence < 20 {
                StatusCode::CREATED
            } else {
                StatusCode::TOO_MANY_REQUESTS
            }
        );
    }
    let mut proxied = json_request("POST", "/api/v1/logins", json!({}));
    proxied.extensions_mut().insert(axum::extract::ConnectInfo(
        "127.0.0.1:1234".parse::<std::net::SocketAddr>().unwrap(),
    ));
    proxied
        .headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_static("198.51.100.1"));
    assert_eq!(fixture.json(proxied).await.0, StatusCode::CREATED);
    fixture.close().await;
}

struct Fixture {
    directory: tempfile::TempDir,
    app: Arc<App>,
    router: Router,
}

impl Fixture {
    async fn new() -> Self {
        Self::with_mtls(false).await
    }

    async fn with_mtls(internal_mtls_required: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings {
            data_dir: directory.path().into(),
            bot_token: "x".repeat(32),
            bot_app_id: "app".into(),
            group_openid: "group".into(),
            internal_mtls_required,
            ..Settings::default()
        };
        let app = App::new(settings).await.unwrap();
        let router = app.router();
        Self {
            directory,
            app,
            router,
        }
    }

    async fn send(&self, request: HttpRequest<Body>) -> Response {
        self.router.clone().oneshot(request).await.unwrap()
    }

    async fn json(&self, request: HttpRequest<Body>) -> (StatusCode, Value) {
        let response = self.send(request).await;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, value)
    }

    async fn seed_management_session(&self) {
        let mut transaction = self.app.database.write().await.unwrap();
        sqlx::query("INSERT INTO accounts(id,login_name,login_normalized,status,created_at) VALUES('account','Alice','alice','active',1)")
            .execute(transaction.connection()).await.unwrap();
        sqlx::query("INSERT INTO profiles(uuid,account_id,name,name_normalized) VALUES(?,'account','Alice','alice')")
            .bind(SEEDED_PROFILE).execute(transaction.connection()).await.unwrap();
        sqlx::query("INSERT INTO tokens VALUES(?,'account','management',NULL,?)")
            .bind(digest("management-token"))
            .bind(now() + 3600)
            .execute(transaction.connection())
            .await
            .unwrap();
        transaction.commit().await.unwrap();
    }

    async fn close(self) {
        let Self {
            directory,
            app,
            router,
        } = self;
        drop(router);
        app.database.pool().close().await;
        drop(app);
        // SQLite closes its worker handle asynchronously after pool shutdown.
        let path = directory.keep();
        for attempt in 0..10 {
            match std::fs::remove_dir_all(&path) {
                Ok(()) => return,
                Err(error) if attempt == 9 => panic!("Cannot remove test data: {error}"),
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
            }
        }
    }
}

fn request(method: &str, path: &str, body: impl Into<Body>) -> HttpRequest<Body> {
    HttpRequest::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "auth.test")
        .body(body.into())
        .unwrap()
}

fn json_request(method: &str, path: &str, body: Value) -> HttpRequest<Body> {
    let mut request = request(method, path, body.to_string());
    request.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    request
}

fn authorized(mut request: HttpRequest<Body>, token: &str) -> HttpRequest<Body> {
    request.headers_mut().insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    request
}

fn event(value: &str, event_id: &str, registration: bool) -> Value {
    let mut fields = json!({"bot_app_id":"app", "group_openid":"group", "member_openid":"member", "event_id":event_id});
    fields[if registration { "name" } else { "code" }] = json!(value);
    fields
}

fn multipart(path: &str, file_field: &str, image: &[u8], model: &str) -> HttpRequest<Body> {
    let mut content = format!(
        "--nomi-boundary\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n{model}\r\n\
         --nomi-boundary\r\nContent-Disposition: form-data; name=\"{file_field}\"; filename=\"skin.png\"\r\n\
         Content-Type: image/png\r\n\r\n"
    ).into_bytes();
    content.extend_from_slice(image);
    content.extend_from_slice(b"\r\n--nomi-boundary--\r\n");
    let mut request = request("PUT", path, content);
    request.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("multipart/form-data; boundary=nomi-boundary"),
    );
    request
}

fn png() -> Vec<u8> {
    let mut output = Cursor::new(Vec::new());
    image::DynamicImage::new_rgba8(64, 64)
        .write_to(&mut output, ImageFormat::Png)
        .unwrap();
    output.into_inner()
}

#[tokio::test]
async fn routing_exposes_only_api_and_preserves_headers_methods_and_redirects() {
    let fixture = Fixture::new().await;
    for path in ["/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"] {
        let response = fixture.send(request("GET", path, Body::empty())).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    }
    let mut health = request("GET", "/health", Body::empty());
    health
        .headers_mut()
        .insert("x-request-id", HeaderValue::from_bytes(&[0xff]).unwrap());
    let response = fixture.send(health).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");

    let response = fixture
        .send(request("POST", "/health", Body::empty()))
        .await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers()[header::ALLOW], "GET");

    for (method, path, destination) in [
        ("GET", "/health/?check=database", "/health?check=database"),
        (
            "POST",
            "/api/v1/logins/?source=launcher",
            "/api/v1/logins?source=launcher",
        ),
    ] {
        let response = fixture.send(request(method, path, Body::empty())).await;
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert!(
            response.headers()[header::LOCATION]
                .to_str()
                .unwrap()
                .ends_with(destination)
        );
    }
    let response = fixture
        .send(request("GET", "https://auth.test/health/", Body::empty()))
        .await;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response.headers()[header::LOCATION].to_str().unwrap();
    assert!(location == "/health" || location == "https://auth.test/health");
    for (peer, expected_scheme) in [("127.0.0.1:1234", "https"), ("192.0.2.1:1234", "http")] {
        let mut redirected = request("GET", "/health/", Body::empty());
        redirected
            .headers_mut()
            .insert("x-forwarded-proto", HeaderValue::from_static("https"));
        redirected
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(
                peer.parse::<std::net::SocketAddr>().unwrap(),
            ));
        let response = fixture.send(redirected).await;
        assert_eq!(
            response.headers()[header::LOCATION],
            format!("{expected_scheme}://auth.test/health")
        );
    }
    fixture.close().await;
}

#[tokio::test]
async fn json_body_defaults_and_media_types_match_existing_clients() {
    let fixture = Fixture::new().await;
    for body in [Body::empty(), Body::from("null"), Body::from("{}")] {
        let response = fixture.send(request("POST", "/api/v1/logins", body)).await;
        assert_eq!(response.status(), StatusCode::CREATED);
    }
    for mime in ["Application/JSON", "application/vnd.nomi+json"] {
        let mut login = request("POST", "/api/v1/logins", "{}");
        login
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_str(mime).unwrap());
        assert_eq!(fixture.send(login).await.status(), StatusCode::CREATED);
    }
    let mut invalid_mime = request("POST", "/api/v1/logins", "{}");
    invalid_mime.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/test+json"),
    );
    assert_eq!(
        fixture.send(invalid_mime).await.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    let response = fixture
        .send(json_request("POST", "/api/v1/registrations", Value::Null))
        .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let (status, error) = fixture
        .json(request(
            "POST",
            "/api/yggdrasil/authserver/authenticate",
            "not json",
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error["error"], "ForbiddenOperationException");
    fixture.close().await;
}

#[tokio::test]
async fn skin_authentication_precedes_image_limits_and_uuid_paths_decode() {
    let fixture = Fixture::new().await;
    fixture.seed_management_session().await;
    let image = vec![b'x'; 1024 * 1024 + 1];
    let (status, error) = fixture
        .json(multipart(
            "/api/v1/me/profile/skin",
            "image",
            &image,
            "default",
        ))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(error["code"], "UNAUTHORIZED");
    let authenticated = authorized(
        multipart("/api/v1/me/profile/skin", "image", &image, "default"),
        "management-token",
    );
    let (status, error) = fixture.json(authenticated).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(error["code"], "INVALID_IMAGE");

    for identifier in [
        format!("%7B{SEEDED_PROFILE}%7D"),
        "%7B12345678-9012-3456-7890-123456789012%7D".into(),
        format!("urn:uuid:{SEEDED_PROFILE}"),
    ] {
        let encoded =
            format!("/api/yggdrasil/sessionserver/session/minecraft/profile/{identifier}");
        let (status, profile) = fixture.json(request("GET", &encoded, Body::empty())).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(profile["id"], SEEDED_PROFILE);
    }
    for path in [
        "/api/yggdrasil/sessionserver/session/minecraft/profile/not-a-uuid",
        "/api/yggdrasil/sessionserver/session/minecraft/profile/00000000000000000000000000000000",
    ] {
        assert_eq!(
            fixture
                .send(request("GET", path, Body::empty()))
                .await
                .status(),
            StatusCode::NO_CONTENT
        );
    }
    let forbidden_segment = "/api/yggdrasil/sessionserver/session/minecraft/profile/id%2Fextra";
    assert_eq!(
        fixture
            .send(request("GET", forbidden_segment, Body::empty()))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    fixture.close().await;
}

#[tokio::test]
async fn group_login_skin_and_game_join_work_through_real_http_extractors() {
    let fixture = Fixture::new().await;
    let (status, login) = fixture
        .json(json_request("POST", "/api/v1/logins", json!({})))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let bot_token = "x".repeat(32);
    let verification = authorized(
        json_request(
            "POST",
            "/internal/v1/logins/verify",
            event(login["code"].as_str().unwrap(), "verify", false),
        ),
        &bot_token,
    );
    assert_eq!(
        fixture.json(verification).await.1["status"],
        "AWAITING_NAME"
    );
    let registration = authorized(
        json_request(
            "POST",
            "/internal/v1/logins/register",
            event("Alice", "register", true),
        ),
        &bot_token,
    );
    let registered = fixture.json(registration).await.1;
    assert_eq!(registered["status"], "REGISTERED");

    let session_path = format!(
        "/api/v1/logins/{}/session",
        login["request_id"].as_str().unwrap()
    );
    let (status, session) = fixture
        .json(authorized(
            request("POST", &session_path, Body::empty()),
            login["poll_token"].as_str().unwrap(),
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    let game_token = session["game"]["accessToken"].as_str().unwrap();
    let management_token = session["management_token"].as_str().unwrap();
    let profile_id = session["game"]["selectedProfile"]["id"].as_str().unwrap();
    assert_eq!(registered["uuid"], profile_id);

    let image = png();
    let upload = authorized(
        multipart("/api/v1/me/profile/skin", "image", &image, "slim"),
        management_token,
    );
    let (status, skin) = fixture.json(upload).await;
    assert_eq!(status, StatusCode::OK);
    let texture_path = format!("/textures/{}", skin["hash"].as_str().unwrap());
    let response = fixture
        .send(request("GET", &texture_path, Body::empty()))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "image/png");
    assert_eq!(
        response.headers()[header::CACHE_CONTROL],
        "public,max-age=31536000,immutable"
    );

    let validate = json_request(
        "POST",
        "/api/yggdrasil/authserver/validate",
        json!({"accessToken":game_token}),
    );
    assert_eq!(
        fixture.send(validate).await.status(),
        StatusCode::NO_CONTENT
    );
    let join = json_request(
        "POST",
        "/api/yggdrasil/sessionserver/session/minecraft/join",
        json!({"accessToken":game_token,"selectedProfile":profile_id,"serverId":"server"}),
    );
    assert_eq!(fixture.send(join).await.status(), StatusCode::NO_CONTENT);
    let (status, joined) = fixture.json(request("GET", "/api/yggdrasil/sessionserver/session/minecraft/hasJoined?username=Alice&serverId=server", Body::empty())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(joined["id"], profile_id);
    let property = &joined["properties"][0];
    let value = property["value"].as_str().unwrap();
    let payload: Value = serde_json::from_slice(&STANDARD.decode(value).unwrap()).unwrap();
    assert_eq!(payload["textures"]["SKIN"]["metadata"]["model"], "slim");
    let metadata = fixture
        .json(request("GET", "/api/yggdrasil/", Body::empty()))
        .await
        .1;
    let public =
        RsaPublicKey::from_public_key_pem(metadata["signaturePublickey"].as_str().unwrap())
            .unwrap();
    let signature = STANDARD
        .decode(property["signature"].as_str().unwrap())
        .unwrap();
    public
        .verify(
            Pkcs1v15Sign::new::<Sha1>(),
            &Sha1::digest(value.as_bytes()),
            &signature,
        )
        .unwrap();

    let native_path = format!("/api/yggdrasil/api/user/profile/{profile_id}/skin");
    let native = authorized(multipart(&native_path, "file", &image, ""), game_token);
    assert_eq!(fixture.send(native).await.status(), StatusCode::NO_CONTENT);
    let wrong_field = authorized(multipart(&native_path, "image", &image, ""), game_token);
    let (status, error) = fixture.json(wrong_field).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["error"], "IllegalArgumentException");
    let clear = authorized(
        request("DELETE", "/api/v1/me/profile/skin", Body::empty()),
        management_token,
    );
    assert_eq!(fixture.send(clear).await.status(), StatusCode::NO_CONTENT);
    fixture.close().await;
}
