use std::sync::Arc;

use serde_json::{Value, json};
use sqlx::{AnyConnection, Row};

use super::accounts::Accounts;
use super::models::{Account, SessionClaim, Token, TokenOptions};
use crate::core::security::{derive_token, digest, now, same, secret, valid_request_id};
use crate::core::{Error, Reply, Request, Result, Settings};
use crate::storage::Database;

#[derive(Clone)]
pub(crate) struct Sessions {
    database: Arc<Database>,
    accounts: Accounts,
}

struct Grant {
    game: String,
    management: String,
    refresh: String,
    nonce: String,
}

impl Sessions {
    pub fn new(_settings: Arc<Settings>, database: Arc<Database>, accounts: Accounts) -> Self {
        Self { database, accounts }
    }

    pub async fn issue(
        &self,
        connection: &mut AnyConnection,
        claim: &SessionClaim<'_>,
        retry_id: Option<&str>,
        poll: Option<&str>,
    ) -> Result<Value> {
        self.validate_claim(claim)?;
        let account_id = claim
            .account_id
            .ok_or_else(|| Error::problem("ACCOUNT_UNAVAILABLE", "账号不可用", 403))?;
        let account = sqlx::query_as::<_, Account>(
            "SELECT id,login_name,status FROM accounts WHERE id=? AND status='active'",
        )
        .bind(account_id)
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| Error::problem("ACCOUNT_UNAVAILABLE", "账号不可用", 403))?;
        let client_token = secret();
        let grant = self
            .create_grant(connection, account_id, &client_token, retry_id, poll)
            .await?;
        if let Some((retry_id, poll)) = retry_id.zip(poll) {
            self.save_login_retry(connection, claim.id, poll, retry_id, &grant)
                .await?;
        }
        sqlx::query(&format!("DELETE FROM {} WHERE id=?", claim.table))
            .bind(claim.id)
            .execute(&mut *connection)
            .await?;
        self.accounts
            .audit(connection, "qq_session_issued", Some(account_id), None)
            .await?;
        let mut result = self
            .format(
                connection,
                &account,
                Some(&client_token),
                &grant.game,
                &grant.refresh,
            )
            .await?;
        result["management_token"] = json!(grant.management);
        Ok(result)
    }

    async fn create_grant(
        &self,
        connection: &mut AnyConnection,
        account_id: &str,
        client_token: &str,
        retry_id: Option<&str>,
        poll: Option<&str>,
    ) -> Result<Grant> {
        let nonce = secret();
        let issued_at = now();
        let derive = |kind| {
            retry_id
                .zip(poll)
                .map(|(request_id, seed)| derive_token(seed, request_id, &nonce, kind))
        };

        // Every token in this grant shares its issue time and has an explicit role.
        let game_value = derive("game");
        let options = TokenOptions {
            client_token: Some(client_token),
            value: game_value.as_deref(),
            issued_at: Some(issued_at),
        };
        let game = self
            .accounts
            .issue_token(connection, account_id, "game", options)
            .await?;
        let management_value = derive("management");
        let options = TokenOptions {
            client_token: None,
            value: management_value.as_deref(),
            issued_at: Some(issued_at),
        };
        let management = self
            .accounts
            .issue_token(connection, account_id, "management", options)
            .await?;
        let refresh_value = derive("refresh");
        let options = TokenOptions {
            client_token: Some(client_token),
            value: refresh_value.as_deref(),
            issued_at: Some(issued_at),
        };
        let refresh = self
            .accounts
            .issue_token(connection, account_id, "refresh", options)
            .await?;
        Ok(Grant {
            game,
            management,
            refresh,
            nonce,
        })
    }

    async fn save_login_retry(
        &self,
        connection: &mut AnyConnection,
        request_id: &str,
        poll: &str,
        retry_id: &str,
        grant: &Grant,
    ) -> Result<()> {
        sqlx::query("INSERT INTO login_retries VALUES(?,?,?,?,?,?,?,?)")
            .bind(request_id)
            .bind(digest(poll))
            .bind(digest(retry_id))
            .bind(&grant.nonce)
            .bind(digest(&grant.game))
            .bind(digest(&grant.refresh))
            .bind(digest(&grant.management))
            .bind(now() + 120)
            .execute(connection)
            .await?;
        Ok(())
    }

    fn validate_claim(&self, claim: &SessionClaim<'_>) -> Result<()> {
        if claim.status != claim.required_status {
            return Err(Error::problem(
                "NOT_VERIFIED",
                "申请尚未验证或已经结束",
                403,
            ));
        }
        if claim.expires_at <= now() {
            return Err(Error::problem(
                "REQUEST_EXPIRED",
                "申请已过期，请重新申请",
                400,
            ));
        }
        if claim.session_issued != 0 {
            return Err(Error::problem(
                "SESSION_ALREADY_ISSUED",
                "登录凭据已领取，请重新发起群验证",
                409,
            ));
        }
        Ok(())
    }

    pub async fn format(
        &self,
        connection: &mut AnyConnection,
        account: &Account,
        client_token: Option<&str>,
        game: &str,
        refresh: &str,
    ) -> Result<Value> {
        let profile = self.accounts.profile(connection, &account.id).await?;
        let records = sqlx::query("SELECT kind,expires_at FROM tokens WHERE hash IN (?,?)")
            .bind(digest(game))
            .bind(digest(refresh))
            .fetch_all(connection)
            .await?;
        let mut game_expiry = None;
        let mut refresh_expiry = None;
        for record in records {
            let kind: String = record.try_get("kind")?;
            let expiry: i64 = record.try_get("expires_at")?;
            if kind == "game" {
                game_expiry = Some(expiry);
            }
            if kind == "refresh" {
                refresh_expiry = Some(expiry);
            }
        }
        let selected = json!({"id":profile.uuid,"name":profile.name});
        Ok(json!({
            "login_name":account.login_name,
            "refresh_token":refresh,
            "refresh_expires_at":refresh_expiry.ok_or_else(Error::internal)?,
            "game_expires_at":game_expiry.ok_or_else(Error::internal)?,
            "game":{"accessToken":game,"clientToken":client_token,"selectedProfile":selected,"availableProfiles":[selected]}
        }))
    }

    pub async fn login_retry(
        &self,
        connection: &mut AnyConnection,
        request: &str,
        poll: &str,
        retry_id: Option<&str>,
    ) -> Result<Option<Value>> {
        let Some(retry_id) = retry_id else {
            return Ok(None);
        };
        let retry = sqlx::query("SELECT poll_hash,request_hash,nonce FROM login_retries WHERE request_id=? AND expires_at>?")
            .bind(request).bind(now()).fetch_optional(&mut *connection).await?;
        let Some(retry) = retry else {
            return Ok(None);
        };
        let poll_hash: String = retry.try_get("poll_hash")?;
        let request_hash: String = retry.try_get("request_hash")?;
        if !same(&poll_hash, &digest(poll)) || !same(&request_hash, &digest(retry_id)) {
            return Ok(None);
        }

        let nonce: String = super::models::text(&retry, "nonce")?;
        let game = derive_token(poll, retry_id, &nonce, "game");
        let refresh = derive_token(poll, retry_id, &nonce, "refresh");
        let account = self
            .accounts
            .token_account(connection, &refresh, "refresh")
            .await?;
        let token = self.token(connection, &digest(&refresh)).await?;
        let mut result = self
            .format(
                connection,
                &account,
                token.client_token.as_deref(),
                &game,
                &refresh,
            )
            .await?;
        result["management_token"] = json!(derive_token(poll, retry_id, &nonce, "management"));
        Ok(Some(result))
    }

    pub fn validate_retry(&self, retry_id: Option<&str>, message: &str) -> Result<()> {
        if retry_id.is_some_and(|value| !valid_request_id(value)) {
            return Err(Error::problem("INVALID_REQUEST", message, 422));
        }
        Ok(())
    }

    pub async fn refresh(&self, request: &Request) -> Result<Reply> {
        let token = request.bearer()?;
        let retry_id = request.request_id.as_deref();
        self.validate_retry(retry_id, "无效的续期请求标识")?;
        let mut transaction = self.database.write().await?;
        let connection = transaction.connection();
        if let Some(result) = self.refresh_retry(connection, token, retry_id).await? {
            transaction.commit().await?;
            return Ok(Reply::ok(result));
        }
        let account = self
            .accounts
            .token_account(connection, token, "refresh")
            .await?;
        let stored = self.token(connection, &digest(token)).await?;
        sqlx::query(
            "DELETE FROM tokens WHERE hash=? OR (account_id=? AND kind='game' AND client_token=?)",
        )
        .bind(digest(token))
        .bind(&account.id)
        .bind(&stored.client_token)
        .execute(&mut *connection)
        .await?;
        let (game, refresh) = self
            .rotate(
                connection,
                &account.id,
                stored.client_token.as_deref(),
                token,
                retry_id,
            )
            .await?;
        let result = self
            .format(
                connection,
                &account,
                stored.client_token.as_deref(),
                &game,
                &refresh,
            )
            .await?;
        transaction.commit().await?;
        Ok(Reply::ok(result))
    }

    async fn refresh_retry(
        &self,
        connection: &mut AnyConnection,
        seed: &str,
        retry_id: Option<&str>,
    ) -> Result<Option<Value>> {
        let Some(retry_id) = retry_id else {
            return Ok(None);
        };
        let retry = sqlx::query(
            "SELECT request_hash,nonce FROM refresh_retries WHERE old_hash=? AND expires_at>?",
        )
        .bind(digest(seed))
        .bind(now())
        .fetch_optional(&mut *connection)
        .await?;
        let Some(retry) = retry else {
            return Ok(None);
        };
        let request_hash: String = retry.try_get("request_hash")?;
        if !same(&request_hash, &digest(retry_id)) {
            return Ok(None);
        }
        let nonce: String = super::models::text(&retry, "nonce")?;
        let game = derive_token(seed, retry_id, &nonce, "game");
        let refresh = derive_token(seed, retry_id, &nonce, "refresh");
        let account = self
            .accounts
            .token_account(connection, &refresh, "refresh")
            .await?;
        let stored = self.token(connection, &digest(&refresh)).await?;
        Ok(Some(
            self.format(
                connection,
                &account,
                stored.client_token.as_deref(),
                &game,
                &refresh,
            )
            .await?,
        ))
    }

    async fn rotate(
        &self,
        connection: &mut AnyConnection,
        account_id: &str,
        client_token: Option<&str>,
        previous: &str,
        retry_id: Option<&str>,
    ) -> Result<(String, String)> {
        let nonce = secret();
        let issued_at = now();
        let game = retry_id.map(|id| derive_token(previous, id, &nonce, "game"));
        let refresh = retry_id.map(|id| derive_token(previous, id, &nonce, "refresh"));
        let options = TokenOptions {
            client_token,
            value: game.as_deref(),
            issued_at: Some(issued_at),
        };
        let game = self
            .accounts
            .issue_token(connection, account_id, "game", options)
            .await?;
        let options = TokenOptions {
            client_token,
            value: refresh.as_deref(),
            issued_at: Some(issued_at),
        };
        let refresh = self
            .accounts
            .issue_token(connection, account_id, "refresh", options)
            .await?;
        if let Some(id) = retry_id {
            sqlx::query("INSERT INTO refresh_retries VALUES(?,?,?,?,?,?)")
                .bind(digest(previous))
                .bind(digest(id))
                .bind(nonce)
                .bind(digest(&game))
                .bind(digest(&refresh))
                .bind(now() + 120)
                .execute(connection)
                .await?;
        }
        Ok((game, refresh))
    }

    pub async fn token(&self, connection: &mut AnyConnection, hash: &str) -> Result<Token> {
        sqlx::query_as::<_, Token>("SELECT account_id,client_token FROM tokens WHERE hash=?")
            .bind(hash)
            .fetch_optional(connection)
            .await?
            .ok_or_else(|| Error::problem("INVALID_TOKEN", "令牌无效或已过期", 403))
    }

    pub async fn revoke(&self, request: &Request) -> Result<Reply> {
        let token = request.bearer()?;
        let mut transaction = self.database.write().await?;
        let connection = transaction.connection();
        let stored = sqlx::query_as::<_, Token>(
            "SELECT account_id,client_token FROM tokens WHERE hash=? AND kind='refresh'",
        )
        .bind(digest(token))
        .fetch_optional(&mut *connection)
        .await?;
        if let Some(stored) = stored {
            sqlx::query("DELETE FROM tokens WHERE account_id=? AND client_token=? AND kind IN ('game','refresh')")
                .bind(stored.account_id).bind(stored.client_token).execute(connection).await?;
        }
        transaction.commit().await?;
        Ok(Reply::empty(204))
    }

    pub async fn logout(&self, request: &Request) -> Result<Reply> {
        let token = request.bearer()?;
        let mut transaction = self.database.write().await?;
        sqlx::query("DELETE FROM tokens WHERE hash=? AND kind='management'")
            .bind(digest(token))
            .execute(transaction.connection())
            .await?;
        transaction.commit().await?;
        Ok(Reply::empty(204))
    }

    pub async fn current_profile(&self, request: &Request, management: bool) -> Result<Reply> {
        let mut connection = self.database.pool().acquire().await?;
        let kind = if management { "management" } else { "game" };
        let account = self
            .accounts
            .token_account(&mut connection, request.bearer()?, kind)
            .await?;
        let profile = self.accounts.profile(&mut connection, &account.id).await?;
        if management {
            return Ok(Reply::ok(
                json!({"login_name":account.login_name,"profile":profile}),
            ));
        }
        Ok(Reply::ok(json!({"id":profile.uuid,"name":profile.name})))
    }
}
