use std::{collections::HashMap, io::Cursor, sync::Arc};

use base64::{Engine, engine::general_purpose::STANDARD};
use image::ImageFormat;
use nomi_auth_neo::{
    core::{
        Request, Settings,
        security::{digest, now},
    },
    services::{Auth, game::Game, skins::SkinService},
    storage::Database,
};
use rsa::{Pkcs1v15Sign, RsaPublicKey, pkcs8::DecodePublicKey};
use serde_json::{Value, json};
use sha1::{Digest, Sha1};

const PROFILE: &str = "12345678901234567890123456789012";

struct Fixture {
    _directory: tempfile::TempDir,
    settings: Arc<Settings>,
    database: Arc<Database>,
    auth: Auth,
    game: Game,
    skins: SkinService,
}

impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let settings = Arc::new(Settings {
            data_dir: directory.path().into(),
            bot_token: "x".repeat(32),
            bot_app_id: "app".into(),
            group_openid: "group".into(),
            ..Settings::default()
        });
        let database = Database::open(&settings).await.unwrap();
        let mut transaction = database.write().await.unwrap();
        sqlx::query("INSERT INTO accounts(id,login_name,login_normalized,status,created_at) VALUES('account','Alice','alice','active',1)")
            .execute(transaction.connection()).await.unwrap();
        sqlx::query("INSERT INTO profiles(uuid,account_id,name,name_normalized) VALUES(?,'account','Alice','alice')")
            .bind(PROFILE).execute(transaction.connection()).await.unwrap();
        for (token, kind) in [("game-token", "game"), ("management-token", "management")] {
            sqlx::query("INSERT INTO tokens VALUES(?,'account',?,'client',?)")
                .bind(digest(token))
                .bind(kind)
                .bind(now() + 3600)
                .execute(transaction.connection())
                .await
                .unwrap();
        }
        transaction.commit().await.unwrap();
        let auth = Auth::new(settings.clone(), database.clone());
        let game = Game::new(settings.clone(), database.clone(), auth.clone())
            .await
            .unwrap();
        let skins = SkinService::new(settings.clone(), database.clone(), auth.clone());
        Self {
            _directory: directory,
            settings,
            database,
            auth,
            game,
            skins,
        }
    }
}

fn request(method: &str, path: &str, body: Value) -> Request {
    Request {
        method: method.into(),
        path: path.into(),
        body,
        ..Request::default()
    }
}

#[tokio::test]
async fn join_verifies_persistent_rsa_signature_and_expiry() {
    let fixture = Fixture::new().await;
    let join = request(
        "POST",
        "/api/yggdrasil/sessionserver/session/minecraft/join",
        json!({"accessToken":"game-token","clientToken":"client","selectedProfile":PROFILE,"serverId":"server"}),
    );
    assert_eq!(fixture.game.handle(&join).await.unwrap().status, 204);
    let joined = Request {
        query: HashMap::from([
            ("username".into(), "Alice".into()),
            ("serverId".into(), "server".into()),
        ]),
        ..request(
            "GET",
            "/api/yggdrasil/sessionserver/session/minecraft/hasJoined",
            Value::Null,
        )
    };
    let response = fixture.game.handle(&joined).await.unwrap().body.unwrap();
    assert_eq!(response["id"], PROFILE);
    let property = &response["properties"][0];
    let value = property["value"].as_str().unwrap();
    let metadata = fixture
        .game
        .handle(&request("GET", "/api/yggdrasil/", Value::Null))
        .await
        .unwrap()
        .body
        .unwrap();
    let public =
        RsaPublicKey::from_public_key_pem(metadata["signaturePublickey"].as_str().unwrap())
            .unwrap();
    public
        .verify(
            Pkcs1v15Sign::new::<Sha1>(),
            &Sha1::digest(value.as_bytes()),
            &STANDARD
                .decode(property["signature"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
    let payload: Value = serde_json::from_slice(&STANDARD.decode(value).unwrap()).unwrap();
    assert_eq!(payload["profileId"], PROFILE);

    let restarted = Game::new(
        fixture.settings.clone(),
        fixture.database.clone(),
        fixture.auth.clone(),
    )
    .await
    .unwrap();
    let restarted_metadata = restarted
        .handle(&request("GET", "/api/yggdrasil", Value::Null))
        .await
        .unwrap()
        .body
        .unwrap();
    assert_eq!(
        metadata["signaturePublickey"],
        restarted_metadata["signaturePublickey"]
    );
    sqlx::query("UPDATE joins SET expires_at=0")
        .execute(fixture.database.pool())
        .await
        .unwrap();
    assert_eq!(fixture.game.handle(&joined).await.unwrap().status, 204);
}

#[tokio::test]
async fn game_refresh_rotates_once_and_checks_selected_profile_and_token_scope() {
    let fixture = Fixture::new().await;
    let invalid = request(
        "POST",
        "/api/yggdrasil/authserver/refresh",
        json!({"accessToken":"game-token","selectedProfile":{"id":"wrong"}}),
    );
    assert_eq!(
        fixture.game.handle(&invalid).await.err().unwrap().status,
        403
    );
    let refreshed = fixture
        .game
        .handle(&request(
            "POST",
            "/api/yggdrasil/authserver/refresh",
            json!({"accessToken":"game-token","clientToken":"client","requestUser":true}),
        ))
        .await
        .unwrap()
        .body
        .unwrap();
    assert_eq!(refreshed["clientToken"], "client");
    assert_eq!(refreshed["selectedProfile"]["id"], PROFILE);
    assert_eq!(refreshed["user"]["id"], "account");
    assert!(
        fixture
            .game
            .handle(&request(
                "POST",
                "/api/yggdrasil/authserver/validate",
                json!({"accessToken":"game-token"})
            ))
            .await
            .is_err()
    );
    let token = refreshed["accessToken"].as_str().unwrap();
    assert_eq!(
        fixture
            .game
            .handle(&request(
                "POST",
                "/api/yggdrasil/authserver/validate",
                json!({"accessToken":token,"clientToken":null})
            ))
            .await
            .unwrap()
            .status,
        204
    );
    assert_eq!(
        fixture
            .game
            .handle(&request(
                "POST",
                "/api/yggdrasil/authserver/validate",
                json!({"accessToken":"management-token"})
            ))
            .await
            .err()
            .unwrap()
            .status,
        403
    );
}

#[tokio::test]
async fn skin_upload_models_ownership_content_addressing_and_clear() {
    let fixture = Fixture::new().await;
    let mut image = Cursor::new(Vec::new());
    image::DynamicImage::new_rgba8(64, 64)
        .write_to(&mut image, ImageFormat::Png)
        .unwrap();
    let image = image.into_inner();
    let management = Request {
        authorization: Some("Bearer management-token".into()),
        ..request("PUT", "/api/v1/me/profile/skin", Value::Null)
    };
    let uploaded = fixture
        .skins
        .upload(&management, image.clone(), "slim")
        .await
        .unwrap()
        .body
        .unwrap();
    let hash = uploaded["hash"].as_str().unwrap();
    assert_eq!(fixture.skins.texture(hash).await.unwrap().status(), 200);
    let profile = fixture
        .game
        .handle(&request(
            "GET",
            &format!("/api/yggdrasil/sessionserver/session/minecraft/profile/{PROFILE}"),
            Value::Null,
        ))
        .await
        .unwrap()
        .body
        .unwrap();
    let property: Value = serde_json::from_slice(
        &STANDARD
            .decode(profile["properties"][0]["value"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(property["textures"]["SKIN"]["metadata"]["model"], "slim");
    let wrong = Request {
        authorization: Some("Bearer game-token".into()),
        ..request(
            "PUT",
            "/api/yggdrasil/api/user/profile/00000000000000000000000000000000/skin",
            Value::Null,
        )
    };
    assert_eq!(
        fixture
            .skins
            .upload(&wrong, image.clone(), "")
            .await
            .err()
            .unwrap()
            .status,
        403
    );
    let own = Request {
        authorization: Some("Bearer game-token".into()),
        ..request(
            "PUT",
            &format!("/api/yggdrasil/api/user/profile/{PROFILE}/skin"),
            Value::Null,
        )
    };
    assert_eq!(
        fixture.skins.upload(&own, image, "").await.unwrap().status,
        204
    );
    assert_eq!(fixture.skins.clear(&management).await.unwrap().status, 204);
    assert!(
        fixture
            .skins
            .texture("../texture-signing.pem")
            .await
            .is_err()
    );
    let mut connection = fixture.database.pool().acquire().await.unwrap();
    assert!(
        fixture
            .auth
            .profile(&mut connection, "account")
            .await
            .unwrap()
            .skin_hash
            .is_none()
    );
}

#[tokio::test]
async fn metadata_reports_the_current_implementation_and_package_version() {
    let fixture = Fixture::new().await;
    let metadata = fixture
        .game
        .handle(&request("GET", "/api/yggdrasil/", json!({})))
        .await
        .unwrap()
        .body
        .unwrap();
    assert_eq!(metadata["meta"]["implementationName"], "Nomi Auth Neo");
    assert_eq!(
        metadata["meta"]["implementationVersion"],
        env!("CARGO_PKG_VERSION")
    );
}
