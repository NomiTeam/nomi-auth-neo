use sqlx::{AnyConnection, Row};

use crate::core::{Error, Result};

pub const SQLITE_SCHEMA: &str = include_str!("schema/sqlite.sql");
pub const MYSQL_SCHEMA: &str = include_str!("schema/mysql.sql");
pub const SCHEMA_VERSION: i64 = 5;

pub async fn check_version(connection: &mut AnyConnection, mysql: bool) -> Result<Vec<i64>> {
    let table_exists = if mysql {
        sqlx::query("SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='schema_versions'")
            .fetch_optional(&mut *connection).await?.is_some()
    } else {
        sqlx::query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_versions'")
            .fetch_optional(&mut *connection)
            .await?
            .is_some()
    };
    if !table_exists {
        return Ok(Vec::new());
    }

    let records = sqlx::query("SELECT version FROM schema_versions")
        .fetch_all(connection)
        .await?;
    let versions: Vec<i64> = records
        .iter()
        .map(|record| record.try_get(0))
        .collect::<std::result::Result<_, _>>()?;
    let latest = versions.iter().copied().max().unwrap_or(0);
    if latest > SCHEMA_VERSION || (mysql && latest != 0 && latest != SCHEMA_VERSION) {
        return Err(Error::problem(
            "UNSUPPORTED_SCHEMA",
            "Database schema is newer or incompatible",
            500,
        ));
    }
    Ok(versions)
}

pub async fn initialize(connection: &mut AnyConnection, mysql: bool) -> Result<()> {
    let versions = check_version(connection, mysql).await?;
    if mysql && versions.is_empty() {
        let tables = sqlx::query("SHOW TABLES")
            .fetch_all(&mut *connection)
            .await?;
        if !tables.is_empty() {
            let names: Vec<String> = tables
                .iter()
                .map(|record| record.try_get(0))
                .collect::<std::result::Result<_, _>>()?;
            if !names.iter().any(|name| name == "schema_versions") {
                return Err(Error::problem(
                    "INVALID_DATABASE",
                    "MySQL requires a dedicated empty database",
                    500,
                ));
            }
        }
    }

    create_tables(connection, mysql).await?;
    if mysql {
        if versions.is_empty() {
            for version in [2_i64, 3, 4, 5] {
                sqlx::query("INSERT INTO schema_versions VALUES(?)")
                    .bind(version)
                    .execute(&mut *connection)
                    .await?;
            }
        }
        return Ok(());
    }
    upgrade_sqlite(connection, &versions).await
}

pub async fn create_tables(connection: &mut AnyConnection, mysql: bool) -> Result<()> {
    let schema = if mysql { MYSQL_SCHEMA } else { SQLITE_SCHEMA };
    for statement in schema
        .split(';')
        .map(str::trim)
        .filter(|statement| !statement.is_empty())
    {
        let statement = if mysql {
            format!("{statement} ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin")
        } else {
            statement.to_owned()
        };
        sqlx::query(&statement).execute(&mut *connection).await?;
    }
    Ok(())
}

async fn upgrade_sqlite(connection: &mut AnyConnection, versions: &[i64]) -> Result<()> {
    remove_passwords(connection).await?;
    sqlx::query("DROP TABLE IF EXISTS recoveries")
        .execute(&mut *connection)
        .await?;
    if !versions.contains(&2) {
        // Sessions from the old password-based mechanism must not cross this boundary.
        sqlx::query("DELETE FROM tokens")
            .execute(&mut *connection)
            .await?;
        sqlx::query("DELETE FROM joins")
            .execute(&mut *connection)
            .await?;
    }

    let login_columns = columns(connection, "login_requests").await?;
    for column in ["app_id", "group_id", "member_id", "error"] {
        if !login_columns.iter().any(|name| name == column) {
            sqlx::query(&format!(
                "ALTER TABLE login_requests ADD COLUMN {column} TEXT"
            ))
            .execute(&mut *connection)
            .await?;
        }
    }
    if !columns(connection, "receipts")
        .await?
        .iter()
        .any(|name| name == "created_at")
    {
        sqlx::query("ALTER TABLE receipts ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0")
            .execute(&mut *connection)
            .await?;
        sqlx::query("UPDATE receipts SET created_at=unixepoch() WHERE created_at=0")
            .execute(&mut *connection)
            .await?;
    }
    for statement in [
        "CREATE INDEX IF NOT EXISTS receipt_created ON receipts(created_at)",
        "CREATE INDEX IF NOT EXISTS audit_created ON audit(created_at)",
    ] {
        sqlx::query(statement).execute(&mut *connection).await?;
    }
    for version in [2_i64, 3, 4, 5] {
        sqlx::query("INSERT OR IGNORE INTO schema_versions VALUES(?)")
            .bind(version)
            .execute(&mut *connection)
            .await?;
    }
    Ok(())
}

async fn remove_passwords(connection: &mut AnyConnection) -> Result<()> {
    for table in ["accounts", "registrations"] {
        let names = columns(connection, table).await?;
        if names.iter().any(|name| name == "password_hash") {
            sqlx::query(&format!("ALTER TABLE {table} DROP COLUMN password_hash"))
                .execute(&mut *connection)
                .await?;
        }
        if table == "registrations" && !names.iter().any(|name| name == "session_issued") {
            sqlx::query(
                "ALTER TABLE registrations ADD COLUMN session_issued INTEGER NOT NULL DEFAULT 0",
            )
            .execute(&mut *connection)
            .await?;
        }
    }
    Ok(())
}

pub async fn columns(connection: &mut AnyConnection, table: &str) -> Result<Vec<String>> {
    let records = sqlx::query(&format!("PRAGMA table_info({table})"))
        .fetch_all(connection)
        .await?;
    Ok(records
        .iter()
        .map(|record| record.try_get(1))
        .collect::<std::result::Result<_, _>>()?)
}
