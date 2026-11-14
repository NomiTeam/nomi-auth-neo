use std::{collections::HashSet, fs, io::Write, path::Path, sync::Arc};

use base64::{Engine, engine::general_purpose::STANDARD};
use rsa::{
    Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey,
    pkcs1::DecodeRsaPrivateKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha1::{Digest, Sha1};
use sqlx::AnyConnection;

use super::{Account, Auth, Profile, TokenOptions};
use crate::{
    core::{
        Error, Reply, Request, Result, Settings,
        security::{digest, now},
    },
    storage::Database,
};

const ROOT: &str = "/api/yggdrasil";

/// Game authentication shares the account rules and persistent signing identity.
#[derive(Clone)]
pub struct Game {
    settings: Arc<Settings>,
    database: Arc<Database>,
    auth: Auth,
    signing_key: Arc<RsaPrivateKey>,
    public_key: String,
}

/// Optional null values are omitted just like Python's exclude_none serialization.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct GameRequest {
    username: String,
    access_token: String,
    client_token: Option<String>,
    selected_profile: Option<Value>,
    server_id: Option<String>,
    #[serde(deserialize_with = "deserialize_boolean")]
    request_user: bool,
}

struct GameSession {
    account: Account,
    profile: Profile,
    token_hash: String,
    client_token: Option<String>,
}

impl GameRequest {
    fn parse(request: &Request) -> Result<Self> {
        let fields: Self = request.parse()?;
        if fields.username.chars().count() > 128 || fields.access_token.chars().count() > 256 {
            return Err(Error::invalid());
        }
        for value in [&fields.client_token, &fields.server_id]
            .into_iter()
            .flatten()
        {
            if value.chars().count() > 256 {
                return Err(Error::invalid());
            }
        }
        if let Some(selected) = &fields.selected_profile {
            let valid = selected.is_string()
                || selected
                    .as_object()
                    .is_some_and(|fields| fields.values().all(Value::is_string));
            if !valid {
                return Err(Error::invalid());
            }
        }
        Ok(fields)
    }
}

impl Game {
    pub async fn new(settings: Arc<Settings>, database: Arc<Database>, auth: Auth) -> Result<Self> {
        let path = settings.data_dir.join("texture-signing.pem");
        let signing_key = tokio::task::spawn_blocking(move || load_signing_key(&path))
            .await
            .map_err(|_| Error::internal())??;
        let public_key = RsaPublicKey::from(&signing_key)
            .to_public_key_pem(LineEnding::LF)
            .map_err(|_| Error::internal())?;
        Ok(Self {
            settings,
            database,
            auth,
            signing_key: Arc::new(signing_key),
            public_key,
        })
    }

    pub async fn handle(&self, request: &Request) -> Result<Reply> {
        let path = request.path.strip_prefix(ROOT).unwrap_or("");
        match (request.method.as_str(), path) {
            ("GET", "" | "/") => self.metadata(),
            ("POST", "/authserver/authenticate" | "/authserver/signout") => Err(Error::problem(
                "QQ_LOGIN_REQUIRED",
                "Use Nomi QQ verification login.",
                403,
            )),
            ("POST", "/authserver/refresh") => self.refresh(request).await,
            ("POST", "/authserver/validate") => self.validate(request).await,
            ("POST", "/authserver/invalidate") => self.invalidate(request).await,
            ("POST", "/sessionserver/session/minecraft/join") => self.join(request).await,
            ("GET", "/sessionserver/session/minecraft/hasJoined") => self.has_joined(request).await,
            ("GET", path) if path.starts_with("/sessionserver/session/minecraft/profile/") => {
                self.get_profile(request, &path[41..]).await
            }
            ("POST", "/api/profiles/minecraft") => self.find_profiles(request).await,
            _ => Err(Error::problem("NOT_FOUND", "Not Found", 404)),
        }
    }

    fn metadata(&self) -> Result<Reply> {
        let hostname = url::Url::parse(&self.settings.public_url)
            .ok()
            .and_then(|address| address.host_str().map(str::to_owned));
        Ok(Reply::ok(json!({
            "meta": {"serverName":"Nomi", "implementationName":"Nomi Auth",
                "implementationVersion":"0.1.0", "feature.non_email_login":true},
            "skinDomains":[hostname], "signaturePublickey":self.public_key,
        })))
    }

    async fn session(
        &self,
        connection: &mut AnyConnection,
        fields: &GameRequest,
    ) -> Result<GameSession> {
        let account = self
            .auth
            .account_for_token(connection, &fields.access_token, "game")
            .await?;
        let token_hash = digest(&fields.access_token);
        let row = sqlx::query("SELECT client_token FROM tokens WHERE hash=?")
            .bind(&token_hash)
            .fetch_one(&mut *connection)
            .await?;
        let client_token: Option<String> = super::models::optional_text(&row, "client_token")?;
        if fields.client_token.is_some() && fields.client_token != client_token {
            return Err(Error::problem("INVALID_TOKEN", "Invalid token.", 403));
        }
        let profile = self.auth.profile(connection, &account.id).await?;
        Ok(GameSession {
            account,
            profile,
            token_hash,
            client_token,
        })
    }

    async fn refresh(&self, request: &Request) -> Result<Reply> {
        let fields = GameRequest::parse(request)?;
        let mut transaction = self.database.write().await?;
        let session = self.session(transaction.connection(), &fields).await?;
        self.check_selected_profile(&fields, &session.profile)?;

        sqlx::query("DELETE FROM tokens WHERE hash=?")
            .bind(&session.token_hash)
            .execute(transaction.connection())
            .await?;
        let options = TokenOptions {
            client_token: session.client_token.as_deref(),
            ..Default::default()
        };
        let access_token = self
            .auth
            .issue_token(
                transaction.connection(),
                &session.account.id,
                "game",
                options,
            )
            .await?;
        transaction.commit().await?;

        let mut response = json!({"accessToken":access_token, "clientToken":session.client_token,
            "selectedProfile":{"id":session.profile.uuid,"name":session.profile.name}});
        if fields.request_user {
            response["user"] = json!({"id":session.account.id,"properties":[]});
        }
        Ok(Reply::ok(response))
    }

    fn check_selected_profile(&self, fields: &GameRequest, profile: &Profile) -> Result<()> {
        let Some(selected) = &fields.selected_profile else {
            return Ok(());
        };
        let empty = selected.as_str() == Some("")
            || selected.as_object().is_some_and(|value| value.is_empty());
        if !empty && selected.get("id").and_then(Value::as_str) != Some(profile.uuid.as_str()) {
            return Err(Error::problem("INVALID_PROFILE", "Invalid profile.", 403));
        }
        Ok(())
    }

    async fn validate(&self, request: &Request) -> Result<Reply> {
        let fields = GameRequest::parse(request)?;
        let mut connection = self.database.pool().acquire().await?;
        self.session(&mut connection, &fields).await?;
        Ok(Reply::empty(204))
    }

    async fn invalidate(&self, request: &Request) -> Result<Reply> {
        let fields = GameRequest::parse(request)?;
        let mut transaction = self.database.write().await?;
        let token_hash = digest(&fields.access_token);
        let row = sqlx::query("SELECT client_token FROM tokens WHERE hash=? AND kind='game'")
            .bind(&token_hash)
            .fetch_optional(transaction.connection())
            .await?;
        if let Some(row) = row {
            let stored_client: Option<String> = super::models::optional_text(&row, "client_token")?;
            if fields.client_token.is_none() || fields.client_token == stored_client {
                sqlx::query("DELETE FROM tokens WHERE hash=?")
                    .bind(&token_hash)
                    .execute(transaction.connection())
                    .await?;
            }
        }
        transaction.commit().await?;
        Ok(Reply::empty(204))
    }

    async fn join(&self, request: &Request) -> Result<Reply> {
        let fields = GameRequest::parse(request)?;
        let server_id = fields
            .server_id
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| Error::problem("INVALID_SESSION", "Invalid server ID.", 400))?;
        let mut transaction = self.database.write().await?;
        let session = self.session(transaction.connection(), &fields).await?;
        if fields.selected_profile.as_ref().and_then(Value::as_str)
            != Some(session.profile.uuid.as_str())
        {
            return Err(Error::problem("INVALID_PROFILE", "Invalid token.", 403));
        }

        sqlx::query("DELETE FROM joins WHERE profile_id=? AND server_id=?")
            .bind(&session.profile.uuid)
            .bind(server_id)
            .execute(transaction.connection())
            .await?;
        sqlx::query("INSERT INTO joins VALUES(?,?,?)")
            .bind(&session.profile.uuid)
            .bind(server_id)
            .bind(now() + 30)
            .execute(transaction.connection())
            .await?;
        transaction.commit().await?;
        Ok(Reply::empty(204))
    }

    async fn has_joined(&self, request: &Request) -> Result<Reply> {
        let username = request.query.get("username").ok_or_else(Error::invalid)?;
        let server_id = request.query.get("serverId").ok_or_else(Error::invalid)?;
        let profile = sqlx::query_as::<_, Profile>(
            "SELECT p.* FROM profiles p JOIN joins j ON p.uuid=j.profile_id \
             JOIN accounts a ON a.id=p.account_id WHERE p.name_normalized=? AND j.server_id=? \
             AND j.expires_at>? AND a.status='active'",
        )
        .bind(username.to_lowercase())
        .bind(server_id)
        .bind(now())
        .fetch_optional(self.database.pool())
        .await?;
        self.profile_reply(profile, true).await
    }

    async fn get_profile(&self, request: &Request, profile_id: &str) -> Result<Reply> {
        let signed = match request.query.get("unsigned") {
            None => false,
            Some(value) => !query_boolean(value)?,
        };
        let Some(profile_id) = normalize_uuid(profile_id) else {
            return Ok(Reply::empty(204));
        };
        let profile = sqlx::query_as::<_, Profile>(
            "SELECT p.* FROM profiles p JOIN accounts a ON a.id=p.account_id \
             WHERE p.uuid=? AND a.status='active'",
        )
        .bind(profile_id)
        .fetch_optional(self.database.pool())
        .await?;
        self.profile_reply(profile, signed).await
    }

    async fn profile_reply(&self, profile: Option<Profile>, signed: bool) -> Result<Reply> {
        match profile {
            Some(profile) => Ok(Reply::ok(self.profile_response(&profile, signed).await?)),
            None => Ok(Reply::empty(204)),
        }
    }

    async fn find_profiles(&self, request: &Request) -> Result<Reply> {
        let names: Vec<String> = request.parse()?;
        if names.len() > 100 {
            return Err(Error::problem("TOO_MANY_NAMES", "Too many names.", 400));
        }
        let mut seen = HashSet::new();
        let mut profiles = Vec::new();
        for name in names {
            let normalized = name.to_lowercase();
            if !seen.insert(normalized.clone()) {
                continue;
            }
            let profile = sqlx::query_as::<_, Profile>(
                "SELECT p.* FROM profiles p JOIN accounts a ON a.id=p.account_id \
                 WHERE p.name_normalized=? AND a.status='active'",
            )
            .bind(normalized)
            .fetch_optional(self.database.pool())
            .await?;
            if let Some(profile) = profile {
                profiles.push(json!({"id":profile.uuid,"name":profile.name}));
            }
        }
        Ok(Reply::ok(Value::Array(profiles)))
    }

    async fn profile_response(&self, profile: &Profile, signed: bool) -> Result<Value> {
        let mut textures = json!({});
        if let Some(texture_hash) = &profile.skin_hash {
            textures["SKIN"] = json!({
                "url":format!("{}/textures/{texture_hash}",self.settings.public_url.trim_end_matches('/')),
                "metadata":{"model":profile.skin_model},
            });
        }
        let payload = json!({"timestamp":now()*1000,"profileId":profile.uuid,
            "profileName":profile.name,"textures":textures});
        let value = STANDARD.encode(serde_json::to_vec(&payload)?);
        let mut texture_property = json!({"name":"textures","value":value});
        if signed {
            // Yggdrasil requires SHA-1 here; changing it would break existing clients.
            let key = self.signing_key.clone();
            let signature_value = value.clone();
            let signature = tokio::task::spawn_blocking(move || {
                key.sign_with_rng(
                    &mut rand::thread_rng(),
                    Pkcs1v15Sign::new::<Sha1>(),
                    &Sha1::digest(signature_value.as_bytes()),
                )
            })
            .await
            .map_err(|_| Error::internal())?
            .map_err(|_| Error::internal())?;
            texture_property["signature"] = json!(STANDARD.encode(signature));
        }
        Ok(
            json!({"id":profile.uuid,"name":profile.name,"properties":[texture_property,
            {"name":"uploadableTextures","value":"skin"}]}),
        )
    }
}

/// Keep the UUID text forms accepted by existing Python clients.
pub(crate) fn normalize_uuid(value: &str) -> Option<String> {
    let value = value.replace("urn:", "").replace("uuid:", "");
    let hexadecimal = value
        .trim_matches(|letter| letter == '{' || letter == '}')
        .replace('-', "");
    if hexadecimal.len() != 32 || !hexadecimal.bytes().all(|letter| letter.is_ascii_hexdigit()) {
        return None;
    }
    Some(hexadecimal.to_ascii_lowercase())
}

fn query_boolean(value: &str) -> Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "on" | "yes" | "t" | "y" => Ok(true),
        "0" | "false" | "off" | "no" | "f" | "n" => Ok(false),
        _ => Err(Error::invalid()),
    }
}

fn deserialize_boolean<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<bool, D::Error> {
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::Bool(value) => Ok(value),
        Value::String(value) => query_boolean(&value).map_err(serde::de::Error::custom),
        Value::Number(value) if value.as_f64() == Some(0.0) => Ok(false),
        Value::Number(value) if value.as_f64() == Some(1.0) => Ok(true),
        _ => Err(serde::de::Error::custom("Invalid boolean")),
    }
}

fn load_signing_key(path: &Path) -> Result<RsaPrivateKey> {
    let directory = path.parent().ok_or_else(Error::internal)?;
    fs::create_dir_all(directory)?;
    if !path.exists() {
        let key =
            RsaPrivateKey::new(&mut rand::thread_rng(), 2048).map_err(|_| Error::internal())?;
        let pem = key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|_| Error::internal())?;
        let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temporary
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        temporary.write_all(pem.as_bytes())?;
        temporary.as_file().sync_all()?;
        // Publish complete PEM bytes atomically, and never replace an existing identity.
        if let Err(error) = temporary.persist_noclobber(path)
            && error.error.kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(error.error.into());
        }
    }
    let pem = fs::read_to_string(path)?;
    RsaPrivateKey::from_pkcs8_pem(&pem)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&pem))
        .map_err(|_| {
            Error::problem(
                "INVALID_SIGNING_KEY",
                "Texture signing key must be a valid RSA private key",
                500,
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_text_forms_match_python() {
        let expected = "abcdef1234567890abcdef1234567890";
        for value in [
            expected.to_uppercase(),
            "abcdef12-3456-7890-abcd-ef1234567890".to_owned(),
            format!("{{{expected}}}"),
            format!("urn:uuid:{expected}"),
            format!("{{{{{expected}}}}}"),
        ] {
            assert_eq!(normalize_uuid(&value).as_deref(), Some(expected));
        }
        for value in [
            "invalid",
            "../texture",
            "URN:UUID:abcdef1234567890abcdef1234567890",
        ] {
            assert!(normalize_uuid(value).is_none());
        }
    }

    #[test]
    fn profile_request_rejects_invalid_shapes_and_keeps_optional_nulls() {
        let request = Request {
            body: json!({"accessToken":"token","clientToken":null}),
            ..Default::default()
        };
        assert!(GameRequest::parse(&request).unwrap().client_token.is_none());
        for selected in [json!(3), json!(["profile"]), json!({"id":false})] {
            let request = Request {
                body: json!({"selectedProfile":selected}),
                ..Default::default()
            };
            assert!(GameRequest::parse(&request).is_err());
        }
        for value in [json!(true), json!(1), json!("YES")] {
            let request = Request {
                body: json!({"requestUser":value}),
                ..Default::default()
            };
            assert!(GameRequest::parse(&request).unwrap().request_user);
        }
    }

    #[test]
    fn signing_key_is_persistent_and_compatible_with_public_verification() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("texture-signing.pem");
        let key = load_signing_key(&path).unwrap();
        let original = fs::read(&path).unwrap();
        let loaded = load_signing_key(&path).unwrap();
        assert_eq!(original, fs::read(&path).unwrap());
        let digest = Sha1::digest(b"base64-property-value");
        let signature = key
            .sign_with_rng(
                &mut rand::thread_rng(),
                Pkcs1v15Sign::new::<Sha1>(),
                &digest,
            )
            .unwrap();
        RsaPublicKey::from(&loaded)
            .verify(Pkcs1v15Sign::new::<Sha1>(), &digest, &signature)
            .unwrap();
    }

    #[test]
    fn invalid_key_is_never_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("texture-signing.pem");
        fs::write(&path, b"invalid-private-key").unwrap();
        assert!(load_signing_key(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"invalid-private-key");
    }
}
