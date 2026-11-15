use std::sync::Arc;

use serde_json::Value;
use sqlx::{AnyConnection, Row};
use uuid::Uuid;

use super::models::{Account, Event, Profile, TokenOptions, parse_result};
use crate::core::security::{digest, now, same, secret};
use crate::core::{Error, Result, Settings};

#[derive(Clone)]
pub(crate) struct Accounts {
    settings: Arc<Settings>,
}

impl Accounts {
    pub fn new(settings: Arc<Settings>) -> Self {
        Self { settings }
    }

    pub async fn token_account(
        &self,
        connection: &mut AnyConnection,
        token: &str,
        kind: &str,
    ) -> Result<Account> {
        let account = sqlx::query_as::<_, Account>(
            "SELECT a.id,a.login_name,a.status FROM tokens t JOIN accounts a ON a.id=t.account_id \
             WHERE t.hash=? AND t.kind=? AND t.expires_at>? AND a.status='active'",
        )
        .bind(digest(token))
        .bind(kind)
        .bind(now())
        .fetch_optional(connection)
        .await?;
        account.ok_or_else(|| Error::problem("INVALID_TOKEN", "令牌无效或已过期", 403))
    }

    pub async fn profile(
        &self,
        connection: &mut AnyConnection,
        account_id: &str,
    ) -> Result<Profile> {
        sqlx::query_as::<_, Profile>("SELECT * FROM profiles WHERE account_id=?")
            .bind(account_id)
            .fetch_optional(connection)
            .await?
            .ok_or_else(|| Error::problem("ACCOUNT_UNAVAILABLE", "账号不可用", 403))
    }

    pub async fn issue_token(
        &self,
        connection: &mut AnyConnection,
        account_id: &str,
        kind: &str,
        options: TokenOptions<'_>,
    ) -> Result<String> {
        let token = options.value.map(str::to_owned).unwrap_or_else(secret);
        let lifetime = match kind {
            "game" => self.settings.game_token_ttl,
            "refresh" => self.settings.refresh_token_ttl,
            "management" => self.settings.management_token_ttl,
            _ => return Err(Error::internal()),
        };
        let expires_at = options
            .issued_at
            .unwrap_or_else(now)
            .checked_add(lifetime)
            .ok_or_else(|| {
                Error::problem("INVALID_CONFIG", "Token lifetime is out of range", 500)
            })?;
        sqlx::query("INSERT INTO tokens VALUES(?,?,?,?,?)")
            .bind(digest(&token))
            .bind(account_id)
            .bind(kind)
            .bind(options.client_token)
            .bind(expires_at)
            .execute(connection)
            .await?;
        Ok(token)
    }

    pub fn check_bot<E: Event>(&self, authorization: &str, event: &E) -> Result<()> {
        if !same(authorization, &self.settings.bot_token) {
            return Err(Error::problem("UNAUTHORIZED", "机器人凭证无效", 401));
        }
        if event.app_id() != self.settings.bot_app_id
            || event.group_id() != self.settings.group_openid
        {
            return Err(Error::problem("WRONG_GROUP", "仅允许指定机器人与群", 400));
        }
        Ok(())
    }

    pub async fn member<E: Event>(
        &self,
        connection: &mut AnyConnection,
        event: &E,
    ) -> Result<Option<Account>> {
        Ok(sqlx::query_as::<_, Account>(
            "SELECT a.id,a.login_name,a.status FROM identities i JOIN accounts a ON a.id=i.account_id \
             WHERE i.app_id=? AND i.group_id=? AND i.member_id=?"
        ).bind(event.app_id()).bind(event.group_id()).bind(event.member_id()).fetch_optional(connection).await?)
    }

    pub async fn name_taken(&self, connection: &mut AnyConnection, name: &str) -> Result<bool> {
        let normalized = name.to_lowercase();
        Ok(sqlx::query("SELECT 1 FROM accounts WHERE login_normalized=? UNION ALL SELECT 1 FROM profiles WHERE name_normalized=?")
            .bind(&normalized).bind(&normalized).fetch_optional(connection).await?.is_some())
    }

    /// The caller owns the transaction and has already checked name and identity.
    pub async fn create<E: Event>(
        &self,
        connection: &mut AnyConnection,
        name: &str,
        event: &E,
    ) -> Result<(String, String)> {
        let (account_id, profile_id) = self.create_unbound(connection, name).await?;
        sqlx::query("INSERT INTO identities VALUES(?,?,?,?)")
            .bind(&account_id)
            .bind(event.app_id())
            .bind(event.group_id())
            .bind(event.member_id())
            .execute(connection)
            .await?;
        Ok((account_id, profile_id))
    }

    /// Create the shared account/profile pair; callers decide whether to bind QQ.
    pub async fn create_unbound(
        &self,
        connection: &mut AnyConnection,
        name: &str,
    ) -> Result<(String, String)> {
        let account_id = Uuid::new_v4().simple().to_string();
        let profile_id = Uuid::new_v4().simple().to_string();
        sqlx::query(
            "INSERT INTO accounts(id,login_name,login_normalized,created_at) VALUES(?,?,?,?)",
        )
        .bind(&account_id)
        .bind(name)
        .bind(name.to_lowercase())
        .bind(now())
        .execute(&mut *connection)
        .await?;
        sqlx::query("INSERT INTO profiles(uuid,account_id,name,name_normalized) VALUES(?,?,?,?)")
            .bind(&profile_id)
            .bind(&account_id)
            .bind(name)
            .bind(name.to_lowercase())
            .execute(&mut *connection)
            .await?;
        Ok((account_id, profile_id))
    }

    pub async fn audit(
        &self,
        connection: &mut AnyConnection,
        action: &str,
        account_id: Option<&str>,
        detail: Option<&str>,
    ) -> Result<()> {
        sqlx::query("INSERT INTO audit(action,account_id,detail,created_at) VALUES(?,?,?,?)")
            .bind(action)
            .bind(account_id)
            .bind(detail)
            .bind(now())
            .execute(connection)
            .await?;
        Ok(())
    }

    pub async fn receipt<E: Event>(
        &self,
        connection: &mut AnyConnection,
        event: &E,
        operation: &str,
    ) -> Result<Option<Value>> {
        let record = sqlx::query("SELECT payload_hash,result FROM receipts WHERE app_id=? AND event_id=? AND operation=?")
            .bind(event.app_id()).bind(event.event_id()).bind(operation).fetch_optional(connection).await?;
        let Some(record) = record else {
            return Ok(None);
        };
        if record.try_get::<String, _>("payload_hash")? != event.payload_hash()? {
            return Err(Error::problem(
                "EVENT_CONFLICT",
                "事件参数与原请求不一致",
                409,
            ));
        }
        Ok(Some(parse_result(&super::models::text(
            &record, "result",
        )?)?))
    }

    pub async fn save_receipt<E: Event>(
        &self,
        connection: &mut AnyConnection,
        event: &E,
        operation: &str,
        result: &Value,
    ) -> Result<()> {
        sqlx::query("INSERT INTO receipts VALUES(?,?,?,?,?,?)")
            .bind(event.app_id())
            .bind(event.event_id())
            .bind(operation)
            .bind(event.payload_hash()?)
            .bind(serde_json::to_string(result)?)
            .bind(now())
            .execute(connection)
            .await?;
        Ok(())
    }
}
