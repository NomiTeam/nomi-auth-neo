use std::sync::Arc;

use sqlx::{AnyConnection, Row};

use super::{Account, models::text, skins::retire_texture};
use crate::{
    core::{Error, Result, security::now},
    storage::Database,
};

/// Local account maintenance shares the same writer lock as HTTP operations.
pub struct Admin {
    database: Arc<Database>,
}

impl Admin {
    pub fn new(database: Arc<Database>) -> Self {
        Self { database }
    }

    async fn account(connection: &mut AnyConnection, name: &str) -> Result<Account> {
        sqlx::query_as::<_, Account>(
            "SELECT id,login_name,status FROM accounts WHERE login_normalized=?",
        )
        .bind(name.to_lowercase())
        .fetch_optional(connection)
        .await?
        .ok_or_else(|| Error::problem("ACCOUNT_NOT_FOUND", "Account not found", 404))
    }

    pub async fn set_enabled(&self, name: &str, enabled: bool) -> Result<()> {
        let mut transaction = self.database.write().await?;
        let connection = transaction.connection();
        let account = Self::account(connection, name).await?;
        let status = if enabled { "active" } else { "disabled" };
        sqlx::query("UPDATE accounts SET status=? WHERE id=?")
            .bind(status)
            .bind(&account.id)
            .execute(&mut *connection)
            .await?;
        Self::revoke(connection, &account.id).await?;
        sqlx::query("INSERT INTO audit(action,account_id,created_at) VALUES(?,?,?)")
            .bind(if enabled { "enable" } else { "disable" })
            .bind(&account.id)
            .bind(now())
            .execute(connection)
            .await?;
        transaction.commit().await
    }

    /// Delete any account, including QQ-bound accounts, without touching other players.
    pub async fn delete(&self, name: &str) -> Result<String> {
        let mut transaction = self.database.write().await?;
        let connection = transaction.connection();
        let account = Self::account(connection, name).await?;
        let profile = sqlx::query("SELECT uuid,skin_hash FROM profiles WHERE account_id=?")
            .bind(&account.id)
            .fetch_optional(&mut *connection)
            .await?;

        self.remove_pending(connection, &account).await?;
        if let Some(profile) = &profile {
            Self::remove_receipts(connection, &profile.try_get::<String, _>("uuid")?).await?;
        }
        Self::revoke(connection, &account.id).await?;
        for table in ["identities", "audit", "profiles"] {
            sqlx::query(&format!("DELETE FROM {table} WHERE account_id=?"))
                .bind(&account.id)
                .execute(&mut *connection)
                .await?;
        }
        sqlx::query("DELETE FROM accounts WHERE id=?")
            .bind(&account.id)
            .execute(&mut *connection)
            .await?;

        // Retire rather than unlink: a concurrent upload may reuse the same texture.
        if let Some(profile) = &profile {
            let hash: Option<String> = profile.try_get("skin_hash")?;
            retire_texture(&self.database.data_dir().join("textures"), hash.as_deref()).await?;
        }
        transaction.commit().await?;
        Ok(account.login_name)
    }

    async fn revoke(connection: &mut AnyConnection, account_id: &str) -> Result<()> {
        sqlx::query(
            "DELETE FROM joins WHERE profile_id IN (SELECT uuid FROM profiles WHERE account_id=?)",
        )
        .bind(account_id)
        .execute(&mut *connection)
        .await?;
        // Retry responses reference tokens with ON DELETE CASCADE on both backends.
        sqlx::query("DELETE FROM tokens WHERE account_id=?")
            .bind(account_id)
            .execute(connection)
            .await?;
        Ok(())
    }

    async fn remove_pending(
        &self,
        connection: &mut AnyConnection,
        account: &Account,
    ) -> Result<()> {
        let identities =
            sqlx::query("SELECT app_id,group_id,member_id FROM identities WHERE account_id=?")
                .bind(&account.id)
                .fetch_all(&mut *connection)
                .await?;
        for identity in identities {
            // A QQ-claimed registration can still have a NULL account_id.
            sqlx::query("DELETE FROM login_requests WHERE app_id=? AND group_id=? AND member_id=?")
                .bind(identity.try_get::<String, _>("app_id")?)
                .bind(identity.try_get::<String, _>("group_id")?)
                .bind(identity.try_get::<String, _>("member_id")?)
                .execute(&mut *connection)
                .await?;
        }
        sqlx::query("DELETE FROM login_requests WHERE account_id=?")
            .bind(&account.id)
            .execute(&mut *connection)
            .await?;
        sqlx::query("DELETE FROM registrations WHERE account_id=? OR LOWER(name)=?")
            .bind(&account.id)
            .bind(account.login_name.to_lowercase())
            .execute(connection)
            .await?;
        Ok(())
    }

    async fn remove_receipts(connection: &mut AnyConnection, profile_id: &str) -> Result<()> {
        let records = sqlx::query(
            "SELECT app_id,event_id,operation,result FROM receipts WHERE result LIKE ?",
        )
        .bind(format!("%{profile_id}%"))
        .fetch_all(&mut *connection)
        .await?;
        for record in records {
            let result: serde_json::Value = serde_json::from_str(&text(&record, "result")?)?;
            if result.get("uuid").and_then(serde_json::Value::as_str) != Some(profile_id) {
                continue;
            }
            sqlx::query("DELETE FROM receipts WHERE app_id=? AND event_id=? AND operation=?")
                .bind(record.try_get::<String, _>("app_id")?)
                .bind(record.try_get::<String, _>("event_id")?)
                .bind(record.try_get::<String, _>("operation")?)
                .execute(&mut *connection)
                .await?;
        }
        Ok(())
    }
}
