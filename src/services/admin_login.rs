use std::sync::Arc;

use sqlx::AnyConnection;

use super::{Account, Profile, accounts::Accounts, logins::Logins};
use crate::{
    core::{Error, Result, security::valid_name},
    storage::Database,
};

/// Approve administrator-selected identities without exposing an HTTP endpoint.
pub(crate) struct AdminLogin {
    database: Arc<Database>,
    accounts: Accounts,
    logins: Logins,
}

impl AdminLogin {
    pub fn new(database: Arc<Database>, accounts: Accounts, logins: Logins) -> Self {
        Self {
            database,
            accounts,
            logins,
        }
    }

    pub async fn approve(&self, code: &str, name: &str) -> Result<Profile> {
        if !valid_name(name) {
            return Err(Error::problem("INVALID_NAME", "Invalid account ID", 400));
        }
        let mut transaction = self.database.write().await?;
        let connection = transaction.connection();
        let request = Logins::pending_code(connection, code).await?;
        if request.status != "PENDING" {
            return Err(Error::problem(
                "CODE_USED",
                "Login request is already claimed",
                409,
            ));
        }

        // Account creation and code approval commit together, or neither persists.
        let account = self.account(connection, name).await?;
        self.logins
            .confirm_login(connection, &request, &account, "admin_login_verified")
            .await?;
        let profile = self.accounts.profile(connection, &account.id).await?;
        transaction.commit().await?;
        Ok(profile)
    }

    async fn account(&self, connection: &mut AnyConnection, name: &str) -> Result<Account> {
        let normalized = name.to_lowercase();
        let account = sqlx::query_as::<_, Account>(
            "SELECT a.id,a.login_name,a.status FROM accounts a LEFT JOIN profiles p ON p.account_id=a.id \
             WHERE a.login_normalized=? OR p.name_normalized=?",
        ).bind(&normalized).bind(&normalized).fetch_optional(&mut *connection).await?;

        if let Some(account) = account {
            if account.status != "active" {
                return Err(Error::problem(
                    "ACCOUNT_UNAVAILABLE",
                    "Account is disabled",
                    403,
                ));
            }
            return Ok(account);
        }

        let (id, _) = self.accounts.create_unbound(connection, name).await?;
        self.accounts
            .audit(connection, "admin_account_created", Some(&id), None)
            .await?;
        Ok(Account {
            id,
            login_name: name.to_owned(),
            status: "active".into(),
        })
    }
}
