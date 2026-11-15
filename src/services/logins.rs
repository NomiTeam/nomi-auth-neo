use std::sync::Arc;

use serde_json::{Value, json};
use sqlx::AnyConnection;
use uuid::Uuid;

use super::accounts::Accounts;
use super::models::{EmptyRequest, LoginRecord, MemberOperation, Redemption};
use super::sessions::Sessions;
use crate::core::security::{code, code_hash, digest, now, same, secret, valid_name};
use crate::core::{Error, Reply, Request, Result, Settings};
use crate::storage::Database;

#[derive(Clone)]
pub(crate) struct Logins {
    settings: Arc<Settings>,
    database: Arc<Database>,
    accounts: Accounts,
    sessions: Sessions,
}

impl Logins {
    pub fn new(
        settings: Arc<Settings>,
        database: Arc<Database>,
        accounts: Accounts,
        sessions: Sessions,
    ) -> Self {
        Self {
            settings,
            database,
            accounts,
            sessions,
        }
    }

    pub async fn start(&self, request: &Request) -> Result<Reply> {
        let _: EmptyRequest = request.parse()?;
        let id = Uuid::new_v4().simple().to_string();
        let verification = code();
        let poll = secret();
        let expires_at = now() + self.settings.registration_ttl;
        let mut transaction = self.database.write().await?;
        sqlx::query("INSERT INTO login_requests(id,code_hash,poll_hash,account_id,expires_at) VALUES(?,?,?,?,?)")
            .bind(&id).bind(code_hash(&verification)).bind(digest(&poll)).bind(Option::<String>::None).bind(expires_at)
            .execute(transaction.connection()).await?;
        transaction.commit().await?;
        Ok(Reply::json(
            201,
            json!({"request_id":id,"code":verification,"poll_token":poll,
            "expires_at":expires_at,"group_label":self.settings.group_label}),
        ))
    }

    pub async fn status(&self, request: &Request, id: &str) -> Result<Reply> {
        let mut transaction = self.database.write().await?;
        let record = self
            .find_request(transaction.connection(), id, request.bearer()?)
            .await?;
        if record.status.as_str() == "FAILED" {
            self.delete(transaction.connection(), id).await?;
        }
        let expired_status = matches!(
            record.status.as_str(),
            "PENDING" | "AWAITING_NAME" | "VERIFIED"
        );
        let status = if expired_status && record.expires_at <= now() {
            "EXPIRED"
        } else {
            record.status.as_str()
        };
        let result =
            json!({"status":status,"expires_at":record.expires_at,"error":record.error.as_deref()});
        transaction.commit().await?;
        Ok(Reply::ok(result))
    }

    pub async fn cancel(&self, request: &Request, id: &str) -> Result<Reply> {
        let mut transaction = self.database.write().await?;
        let record = self
            .find_request(transaction.connection(), id, request.bearer()?)
            .await?;
        let cancellable = record.status.as_str() == "PENDING"
            || matches!(record.status.as_str(), "AWAITING_NAME" | "VERIFIED");
        if !cancellable {
            return Err(Error::problem("ALREADY_FINISHED", "申请已结束", 409));
        }
        self.delete(transaction.connection(), id).await?;
        transaction.commit().await?;
        Ok(Reply::ok(json!({"status":"CANCELLED"})))
    }

    async fn delete(&self, connection: &mut AnyConnection, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM login_requests WHERE id=?")
            .bind(id)
            .execute(connection)
            .await?;
        Ok(())
    }

    async fn find_request(
        &self,
        connection: &mut AnyConnection,
        id: &str,
        poll: &str,
    ) -> Result<LoginRecord> {
        let pending = sqlx::query_as::<_, LoginRecord>("SELECT id,poll_hash,account_id,status,expires_at,session_issued,app_id,group_id,member_id,error FROM login_requests WHERE id=?")
            .bind(id).fetch_optional(connection).await?
            .filter(|record| same(&record.poll_hash, &digest(poll)));
        pending.ok_or_else(|| Error::problem("NOT_FOUND", "申请不存在或凭证无效", 404))
    }

    pub async fn exchange(&self, request: &Request, id: &str) -> Result<Reply> {
        let poll = request.bearer()?;
        let retry_id = request.request_id.as_deref();
        self.sessions
            .validate_retry(retry_id, "无效的登录请求标识")?;
        let mut transaction = self.database.write().await?;
        if let Some(result) = self
            .sessions
            .login_retry(transaction.connection(), id, poll, retry_id)
            .await?
        {
            transaction.commit().await?;
            return Ok(Reply::ok(result));
        }
        let record = self
            .find_request(transaction.connection(), id, poll)
            .await?;
        let result = self
            .sessions
            .issue(transaction.connection(), &record, retry_id, Some(poll))
            .await?;
        transaction.commit().await?;
        Ok(Reply::ok(result))
    }

    pub async fn verify(&self, request: &Request) -> Result<Reply> {
        let event: Redemption = request.parse()?;
        event.validate()?;
        self.accounts.check_bot(request.bearer()?, &event)?;
        let mut transaction = self.database.write().await?;
        let connection = transaction.connection();
        if let Some(result) = self.accounts.receipt(connection, &event, "login").await? {
            transaction.commit().await?;
            return Ok(Reply::ok(result));
        }
        let record = sqlx::query_as::<_, LoginRecord>("SELECT id,poll_hash,account_id,status,expires_at,session_issued,app_id,group_id,member_id,error FROM login_requests WHERE code_hash=?")
            .bind(code_hash(&event.code)).fetch_optional(&mut *connection).await?
            .filter(|record| record.expires_at>now())
            .ok_or_else(|| Error::problem("INVALID_CODE", "登录验证码无效或过期", 400))?;
        let same_member = record.app_id.as_deref() == Some(event.bot_app_id.as_str())
            && record.group_id.as_deref() == Some(event.group_openid.as_str())
            && record.member_id.as_deref() == Some(event.member_openid.as_str());
        if record.status == "AWAITING_NAME" && same_member {
            transaction.commit().await?;
            return Ok(Reply::ok(json!({"status":"AWAITING_NAME"})));
        }
        if record.status != "PENDING" {
            return Err(Error::problem(
                "CODE_USED",
                "登录验证码已使用或申请已结束",
                409,
            ));
        }
        let result = match self.accounts.member(connection, &event).await? {
            Some(account) => self.confirm_login(connection, &record, &account).await?,
            None => self.claim_registration(connection, &record, &event).await?,
        };
        self.accounts
            .save_receipt(connection, &event, "login", &result)
            .await?;
        transaction.commit().await?;
        Ok(Reply::ok(result))
    }

    async fn claim_registration(
        &self,
        connection: &mut AnyConnection,
        record: &LoginRecord,
        event: &Redemption,
    ) -> Result<Value> {
        let pending = sqlx::query("SELECT 1 FROM login_requests WHERE app_id=? AND group_id=? AND member_id=? AND status='AWAITING_NAME' AND expires_at>?")
            .bind(&event.bot_app_id).bind(&event.group_openid).bind(&event.member_openid).bind(now()).fetch_optional(&mut *connection).await?;
        if pending.is_some() {
            return Err(Error::problem(
                "REQUEST_IN_PROGRESS",
                "你已有待注册申请，请先完成或关闭它",
                409,
            ));
        }
        sqlx::query("UPDATE login_requests SET status='AWAITING_NAME',app_id=?,group_id=?,member_id=? WHERE id=?")
            .bind(&event.bot_app_id).bind(&event.group_openid).bind(&event.member_openid).bind(&record.id).execute(connection).await?;
        Ok(json!({"status":"AWAITING_NAME"}))
    }

    async fn confirm_login(
        &self,
        connection: &mut AnyConnection,
        record: &LoginRecord,
        account: &super::models::Account,
    ) -> Result<Value> {
        if account.status != "active" {
            return Err(Error::problem("ACCOUNT_UNAVAILABLE", "账号已停用", 403));
        }
        sqlx::query("UPDATE login_requests SET status='VERIFIED',account_id=? WHERE id=?")
            .bind(&account.id)
            .bind(&record.id)
            .execute(&mut *connection)
            .await?;
        let profile = self.accounts.profile(connection, &account.id).await?;
        self.accounts
            .audit(connection, "qq_login_verified", Some(&account.id), None)
            .await?;
        Ok(json!({"status":"VERIFIED","name":profile.name,"uuid":profile.uuid}))
    }

    pub async fn register(&self, request: &Request) -> Result<Reply> {
        let event: MemberOperation = request.parse()?;
        event.validate()?;
        self.accounts.check_bot(request.bearer()?, &event)?;
        let mut transaction = self.database.write().await?;
        let connection = transaction.connection();
        if let Some(result) = self
            .accounts
            .receipt(connection, &event, "login_register")
            .await?
        {
            transaction.commit().await?;
            return Ok(Reply::ok(result));
        }
        let record = sqlx::query_as::<_, LoginRecord>("SELECT id,poll_hash,account_id,status,expires_at,session_issued,app_id,group_id,member_id,error FROM login_requests WHERE app_id=? AND group_id=? AND member_id=? AND status='AWAITING_NAME' ORDER BY expires_at DESC LIMIT 1")
            .bind(&event.bot_app_id).bind(&event.group_openid).bind(&event.member_openid).fetch_optional(&mut *connection).await?
            .ok_or_else(|| Error::problem("NO_PENDING_REGISTRATION", "没有待注册申请，请先发送启动器的登录码", 409))?;
        let result =
            if let Some(error) = self.registration_error(connection, &record, &event).await? {
                sqlx::query("UPDATE login_requests SET status='FAILED',error=? WHERE id=?")
                    .bind(error)
                    .bind(&record.id)
                    .execute(&mut *connection)
                    .await?;
                json!({"status":"FAILED","code":error})
            } else {
                let (account_id, profile_id) = self
                    .accounts
                    .create(connection, &event.name, &event)
                    .await?;
                sqlx::query("UPDATE login_requests SET status='VERIFIED',account_id=? WHERE id=?")
                    .bind(&account_id)
                    .bind(&record.id)
                    .execute(&mut *connection)
                    .await?;
                self.accounts
                    .audit(connection, "qq_register", Some(&account_id), None)
                    .await?;
                json!({"status":"REGISTERED","name":event.name,"uuid":profile_id})
            };
        self.accounts
            .save_receipt(connection, &event, "login_register", &result)
            .await?;
        transaction.commit().await?;
        Ok(Reply::ok(result))
    }

    async fn registration_error(
        &self,
        connection: &mut AnyConnection,
        record: &LoginRecord,
        event: &MemberOperation,
    ) -> Result<Option<&'static str>> {
        if record.expires_at <= now() {
            return Ok(Some("REQUEST_EXPIRED"));
        }
        if !valid_name(&event.name) {
            return Ok(Some("INVALID_NAME"));
        }
        if self.accounts.member(connection, event).await?.is_some() {
            return Ok(Some("IDENTITY_ALREADY_BOUND"));
        }
        if self.accounts.name_taken(connection, &event.name).await? {
            return Ok(Some("NAME_TAKEN"));
        }
        Ok(None)
    }
}
