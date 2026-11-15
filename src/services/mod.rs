mod accounts;
pub mod game;
mod logins;
mod models;
mod profiles;
mod sessions;
pub mod skins;
mod testing;

use std::sync::Arc;

use serde_json::{Value, json};
use sqlx::AnyConnection;

use crate::core::{Error, Reply, Request, Result, Settings};
use crate::storage::Database;
use accounts::Accounts;
use logins::Logins;
use profiles::Profiles;
use sessions::Sessions;

pub use models::{Account, Profile, TokenOptions};

/// Compose account rules once and share them across launcher and game protocols.
#[derive(Clone)]
pub struct Auth {
    database: Arc<Database>,
    accounts: Accounts,
    logins: Logins,
    sessions: Sessions,
    profiles: Profiles,
}

impl Auth {
    /// Local administration only: this operation has no HTTP route.
    pub async fn test_login(&self, code: &str, name: &str) -> Result<Profile> {
        testing::TestAccounts::new(
            self.database.clone(),
            self.accounts.clone(),
            self.logins.clone(),
        )
        .approve(code, name)
        .await
    }

    pub fn new(settings: Arc<Settings>, database: Arc<Database>) -> Self {
        let accounts = Accounts::new(settings.clone());
        let sessions = Sessions::new(settings.clone(), database.clone(), accounts.clone());
        let logins = Logins::new(
            settings.clone(),
            database.clone(),
            accounts.clone(),
            sessions.clone(),
        );
        let profiles = Profiles::new(settings, database.clone(), accounts.clone());
        Self {
            database,
            accounts,
            logins,
            sessions,
            profiles,
        }
    }

    pub async fn handle(&self, request: &Request) -> Result<Reply> {
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/health") => {
                sqlx::query("SELECT 1")
                    .fetch_one(self.database.pool())
                    .await?;
                Ok(Reply::ok(json!({"status":"ok"})))
            }
            ("POST", "/api/v1/logins") => self.logins.start(request).await,
            ("POST", "/internal/v1/logins/verify") => self.logins.verify(request).await,
            ("POST", "/internal/v1/logins/register") => self.logins.register(request).await,
            ("POST", "/internal/v1/profiles/rename") => self.profiles.rename_member(request).await,
            ("POST", "/api/v1/sessions/refresh") => self.sessions.refresh(request).await,
            ("DELETE", "/api/v1/sessions/refresh") => self.sessions.revoke(request).await,
            ("DELETE", "/api/v1/sessions/current") => self.sessions.logout(request).await,
            ("GET", "/api/v1/game/profile") => self.sessions.current_profile(request).await,
            _ => self.handle_path(request).await,
        }
    }

    async fn handle_path(&self, request: &Request) -> Result<Reply> {
        let parts: Vec<_> = request.path.trim_matches('/').split('/').collect();
        if parts.len() >= 4 && parts[..2] == ["api", "v1"] && parts[2] == "logins" {
            match (request.method.as_str(), parts.len()) {
                ("GET", 4) => return self.logins.status(request, parts[3]).await,
                ("DELETE", 4) => return self.logins.cancel(request, parts[3]).await,
                ("POST", 5) if parts[4] == "session" => {
                    return self.logins.exchange(request, parts[3]).await;
                }
                _ => {}
            }
        }
        if request.method == "PATCH"
            && parts.len() == 6
            && parts[..4] == ["api", "v1", "game", "profiles"]
            && parts[5] == "name"
        {
            return self.profiles.rename(request, parts[4]).await;
        }
        Err(Error::problem("NOT_FOUND", "Not Found", 404))
    }

    pub async fn account_for_token(
        &self,
        connection: &mut AnyConnection,
        token: &str,
        kind: &str,
    ) -> Result<Account> {
        self.accounts.token_account(connection, token, kind).await
    }

    pub async fn profile(
        &self,
        connection: &mut AnyConnection,
        account_id: &str,
    ) -> Result<Profile> {
        self.accounts.profile(connection, account_id).await
    }

    pub async fn issue_token(
        &self,
        connection: &mut AnyConnection,
        account_id: &str,
        kind: &str,
        options: TokenOptions<'_>,
    ) -> Result<String> {
        self.accounts
            .issue_token(connection, account_id, kind, options)
            .await
    }

    pub async fn rename_profile(
        &self,
        connection: &mut AnyConnection,
        account_id: &str,
        name: &str,
    ) -> Result<Value> {
        self.profiles
            .rename_profile(connection, account_id, name)
            .await
    }
}
