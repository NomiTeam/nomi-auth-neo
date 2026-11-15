use std::sync::Arc;

use serde_json::{Value, json};
use sqlx::AnyConnection;

use super::accounts::Accounts;
use super::models::{MemberOperation, NameRequest};
use crate::core::security::{digest, now, valid_name};
use crate::core::{Error, Reply, Request, Result, Settings};
use crate::storage::Database;

#[derive(Clone)]
pub(crate) struct Profiles {
    settings: Arc<Settings>,
    database: Arc<Database>,
    accounts: Accounts,
}

impl Profiles {
    pub fn new(settings: Arc<Settings>, database: Arc<Database>, accounts: Accounts) -> Self {
        Self {
            settings,
            database,
            accounts,
        }
    }

    /// A name is mutable, but the profile row and registered UUID are never replaced.
    pub async fn rename_profile(
        &self,
        connection: &mut AnyConnection,
        account_id: &str,
        name: &str,
    ) -> Result<Value> {
        if !valid_name(name) {
            return Err(Error::problem(
                "INVALID_NAME",
                "名称须为 3 至 16 位字母、数字或下划线",
                400,
            ));
        }
        let profile = self.accounts.profile(connection, account_id).await?;
        let collision = sqlx::query("SELECT 1 FROM profiles WHERE name_normalized=? AND uuid<>? UNION ALL SELECT 1 FROM accounts WHERE login_normalized=? AND id<>?")
            .bind(name.to_lowercase())
            .bind(&profile.uuid)
            .bind(name.to_lowercase())
            .bind(account_id)
            .fetch_optional(&mut *connection)
            .await?;
        if collision.is_some() {
            return Err(Error::problem("NAME_TAKEN", "游戏名已被使用", 409));
        }
        if profile.name == name {
            return Ok(json!({"uuid":profile.uuid,"name":name}));
        }
        if profile.last_renamed_at.is_some_and(|changed| {
            changed != 0 && changed.saturating_add(self.settings.rename_cooldown) > now()
        }) {
            return Err(Error::problem("RENAME_COOLDOWN", "尚在改名冷却期", 409));
        }
        sqlx::query("UPDATE profiles SET name=?,name_normalized=?,last_renamed_at=? WHERE uuid=?")
            .bind(name)
            .bind(name.to_lowercase())
            .bind(now())
            .bind(&profile.uuid)
            .execute(&mut *connection)
            .await?;
        sqlx::query("UPDATE accounts SET login_name=?,login_normalized=? WHERE id=?")
            .bind(name)
            .bind(name.to_lowercase())
            .bind(account_id)
            .execute(&mut *connection)
            .await?;
        let detail = serde_json::to_string(&json!({"old":profile.name,"new":name}))?;
        self.accounts
            .audit(connection, "rename", Some(account_id), Some(&detail))
            .await?;
        Ok(json!({"uuid":profile.uuid,"name":name}))
    }

    pub async fn rename(&self, request: &Request, game_profile: &str) -> Result<Reply> {
        let payload: NameRequest = request.parse()?;
        if !valid_name(&payload.name) {
            return Err(Error::invalid());
        }
        let token = request.bearer()?;
        let mut transaction = self.database.write().await?;
        let connection = transaction.connection();
        let account = self
            .accounts
            .token_account(connection, token, "game")
            .await?;
        let profile = self.accounts.profile(connection, &account.id).await?;
        if game_profile.replace('-', "") != profile.uuid {
            return Err(Error::problem(
                "PROFILE_MISMATCH",
                "只能修改自己的角色",
                403,
            ));
        }
        self.rename_profile(connection, &account.id, &payload.name)
            .await?;
        let record = sqlx::query("SELECT client_token FROM tokens WHERE hash=?")
            .bind(digest(token))
            .fetch_one(&mut *connection)
            .await?;
        let client_token = super::models::optional_text(&record, "client_token")?;
        let selected = json!({"id":profile.uuid,"name":payload.name});
        let result = json!({"login_name":payload.name,"game":{"accessToken":token,"clientToken":client_token,
            "selectedProfile":selected,"availableProfiles":[selected]}});
        transaction.commit().await?;
        Ok(Reply::ok(result))
    }

    pub async fn rename_member(&self, request: &Request) -> Result<Reply> {
        let event: MemberOperation = request.parse()?;
        event.validate()?;
        self.accounts.check_bot(request.bearer()?, &event)?;
        let mut transaction = self.database.write().await?;
        let connection = transaction.connection();
        if let Some(result) = self.accounts.receipt(connection, &event, "rename").await? {
            transaction.commit().await?;
            return Ok(Reply::ok(result));
        }
        let result = match self.rename_for_member(connection, &event).await {
            Ok(result) => result,
            // Only user-level failures are persisted. Driver failures must be retried.
            Err(error) if error.status < 500 => json!({"status":"FAILED","code":error.code}),
            Err(error) => return Err(error),
        };
        self.accounts
            .save_receipt(connection, &event, "rename", &result)
            .await?;
        transaction.commit().await?;
        Ok(Reply::ok(result))
    }

    async fn rename_for_member(
        &self,
        connection: &mut AnyConnection,
        event: &MemberOperation,
    ) -> Result<Value> {
        let account = self
            .accounts
            .member(connection, event)
            .await?
            .ok_or_else(|| Error::problem("ACCOUNT_NOT_FOUND", "尚未注册账号", 404))?;
        if account.status != "active" {
            return Err(Error::problem("ACCOUNT_UNAVAILABLE", "账号已停用", 403));
        }
        let renamed = self
            .rename_profile(connection, &account.id, &event.name)
            .await?;
        Ok(json!({"status":"RENAMED","uuid":renamed["uuid"],"name":renamed["name"]}))
    }
}
