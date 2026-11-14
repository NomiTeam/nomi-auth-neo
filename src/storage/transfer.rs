use std::{collections::BTreeMap, path::Path};

use sqlx::{AnyConnection, Column, Executor, Row, ValueRef, any::AnyRow};

use super::{Database, database::sqlite_url, schema};
use crate::core::{Error, Result, Settings};

pub const TABLES: &[&str] = &[
    "schema_versions",
    "accounts",
    "profiles",
    "identities",
    "registrations",
    "receipts",
    "tokens",
    "joins",
    "login_requests",
    "audit",
    "refresh_retries",
    "login_retries",
];

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Field {
    Null,
    Integer(i64),
    Text(String),
}

/// Copy a locked SQL connection into the same SQLite format used by Python backups.
pub async fn export_sqlite(
    source: &mut AnyConnection,
    destination: &Path,
) -> Result<BTreeMap<String, usize>> {
    if destination.exists()
        || destination.file_name().and_then(|name| name.to_str()) != Some("nomi-auth.sqlite3")
    {
        return Err(data_error(
            "Snapshot destination must be a new nomi-auth.sqlite3 file",
        ));
    }
    let settings = Settings {
        data_dir: destination.parent().ok_or_else(Error::internal)?.to_owned(),
        ..Settings::default()
    };
    let target = Database::open(&settings).await?;
    let result = async {
        let mut transaction = target.write().await?;
        sqlx::query("DELETE FROM schema_versions")
            .execute(transaction.connection())
            .await?;
        let counts = copy_rows(source, transaction.connection()).await?;
        transaction.commit().await?;
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(target.pool())
            .await?;
        Ok(counts)
    }
    .await;
    target.pool().close().await;
    result
}

/// Import only into an empty MySQL/MariaDB database. Every field is verified before commit.
pub async fn import_sqlite(
    source_path: &Path,
    target: &Database,
) -> Result<BTreeMap<String, usize>> {
    if !target.is_mysql() {
        return Err(data_error(
            "Migration destination must use mysql or mariadb",
        ));
    }
    if !source_path.is_file() {
        return Err(data_error("Source SQLite file does not exist"));
    }
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect(&sqlite_url(source_path, true)?)
        .await?;
    let result = async {
        let mut source = pool.acquire().await?;
        source.close_on_drop();
        sqlx::query("BEGIN").execute(&mut *source).await?;
        validate_source(&mut source).await?;

        let mut transaction = target.write().await?;
        check_empty(transaction.connection()).await?;
        sqlx::query("DELETE FROM schema_versions")
            .execute(transaction.connection())
            .await?;
        let counts = copy_rows(&mut source, transaction.connection()).await?;
        verify_rows(&mut source, transaction.connection(), &counts).await?;
        transaction.commit().await?;
        Ok(counts)
    }
    .await;
    pool.close().await;
    result
}

pub(crate) async fn validate_source(connection: &mut AnyConnection) -> Result<()> {
    let result: String = sqlx::query("PRAGMA integrity_check")
        .fetch_one(&mut *connection)
        .await?
        .try_get(0)?;
    if result != "ok"
        || sqlx::query("PRAGMA foreign_key_check")
            .fetch_optional(&mut *connection)
            .await?
            .is_some()
    {
        return Err(data_error(
            "Snapshot database is corrupt or has invalid references",
        ));
    }
    let versions = schema::check_version(connection, false).await?;
    if versions.iter().copied().max() != Some(5) || !versions.contains(&2) {
        return Err(data_error(
            "Upgrade the source SQLite database to schema 5 before migration",
        ));
    }
    Ok(())
}

async fn check_empty(connection: &mut AnyConnection) -> Result<()> {
    for table in TABLES.iter().filter(|table| **table != "schema_versions") {
        if sqlx::query(&format!("SELECT 1 FROM {table} LIMIT 1"))
            .fetch_optional(&mut *connection)
            .await?
            .is_some()
        {
            return Err(data_error(
                "Destination database is not empty; refusing to overwrite",
            ));
        }
    }
    Ok(())
}

async fn copy_rows(
    source: &mut AnyConnection,
    target: &mut AnyConnection,
) -> Result<BTreeMap<String, usize>> {
    let mut counts = BTreeMap::new();
    for table in TABLES {
        let description = source.describe(&format!("SELECT * FROM {table}")).await?;
        let columns: Vec<String> = description
            .columns()
            .iter()
            .map(|column| column.name().to_owned())
            .collect();
        let records = sqlx::query(&format!("SELECT * FROM {table}"))
            .fetch_all(&mut *source)
            .await?;
        let statement = format!(
            "INSERT INTO {table} ({}) VALUES({})",
            columns.join(","),
            vec!["?"; columns.len()].join(",")
        );
        for record in &records {
            let mut query = sqlx::query(&statement);
            for field in record_fields(table, &columns, record)? {
                query = match field {
                    Field::Null => query.bind(Option::<String>::None),
                    Field::Integer(value) => query.bind(value),
                    Field::Text(value) => query.bind(value),
                };
            }
            query.execute(&mut *target).await?;
        }
        counts.insert((*table).to_owned(), records.len());
    }
    Ok(counts)
}

async fn verify_rows(
    source: &mut AnyConnection,
    target: &mut AnyConnection,
    counts: &BTreeMap<String, usize>,
) -> Result<()> {
    for table in TABLES {
        let columns = schema::columns(source, table).await?;
        let expected = table_values(source, table, &columns).await?;
        let actual = table_values(target, table, &columns).await?;
        if actual.len() != counts[*table] || expected != actual {
            return Err(data_error("Imported rows differ from the source database"));
        }
    }
    Ok(())
}

async fn table_values(
    connection: &mut AnyConnection,
    table: &str,
    columns: &[String],
) -> Result<Vec<Vec<Field>>> {
    let records = sqlx::query(&format!("SELECT {} FROM {table}", columns.join(",")))
        .fetch_all(connection)
        .await?;
    let mut values = records
        .iter()
        .map(|record| record_fields(table, columns, record))
        .collect::<Result<Vec<_>>>()?;
    values.sort();
    Ok(values)
}

fn record_fields(table: &str, columns: &[String], record: &AnyRow) -> Result<Vec<Field>> {
    columns
        .iter()
        .map(|column| {
            if record.try_get_raw(column.as_str())?.is_null() {
                return Ok(Field::Null);
            }
            let numeric = matches!(
                column.as_str(),
                "version" | "created_at" | "last_renamed_at" | "expires_at" | "session_issued"
            ) || (table == "audit" && column == "id");
            if numeric {
                Ok(Field::Integer(record.try_get(column.as_str())?))
            } else {
                // MySQL's wire protocol exposes UTF-8 TEXT columns as blobs in Any.
                let text = match record.try_get::<String, _>(column.as_str()) {
                    Ok(value) => value,
                    Err(_) => String::from_utf8(record.try_get::<Vec<u8>, _>(column.as_str())?)
                        .map_err(|_| data_error("Database text is not valid UTF-8"))?,
                };
                Ok(Field::Text(text))
            }
        })
        .collect()
}

fn data_error(message: &str) -> Error {
    Error::problem("INVALID_DATABASE", message, 500)
}
