use std::{
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use sqlx::{
    Any, AnyConnection, AnyPool, Row,
    any::{AnyConnectOptions, AnyPoolOptions},
    pool::PoolConnection,
};
use tokio::sync::{Mutex, OwnedMutexGuard};

use super::schema;
use crate::core::{Error, Result, Settings, security::digest};

/// Database transactions retain the ordering guarantees of the existing service.
pub struct Database {
    pool: AnyPool,
    mysql: bool,
    data_dir: PathBuf,
    writer: Arc<Mutex<()>>,
    cleanup_time: Mutex<Option<i64>>,
    lock_name: String,
    timeout: Duration,
}

/// Unfinished connections are closed rather than returned with a live transaction.
pub struct WriteTransaction {
    connection: PoolConnection<Any>,
    _guard: OwnedMutexGuard<()>,
    mysql: bool,
    lock_name: String,
}

impl Database {
    pub async fn open(settings: &Settings) -> Result<Arc<Self>> {
        sqlx::any::install_default_drivers();
        create_data_directory(&settings.data_dir)?;
        let mysql = match settings.database_backend.as_str() {
            "sqlite" => false,
            "mysql" | "mariadb" => true,
            _ => {
                return Err(Error::problem(
                    "INVALID_CONFIG",
                    "Unsupported database backend",
                    500,
                ));
            }
        };
        let timeout = Duration::from_secs(settings.database_timeout);
        let url = connection_url(settings)?;
        if !mysql && settings.data_dir.join("nomi-auth.sqlite3").is_file() {
            check_sqlite_file(&settings.data_dir.join("nomi-auth.sqlite3")).await?;
        }

        let options = AnyConnectOptions::from_str(&url).map_err(|_| {
            Error::problem("INVALID_CONFIG", "Invalid database connection options", 500)
        })?;
        let pool = AnyPoolOptions::new()
            .max_connections(8)
            .min_connections(1)
            .acquire_timeout(timeout)
            .after_connect(move |connection, _| {
                Box::pin(async move {
                    if mysql {
                        sqlx::query(
                            "SET SESSION sql_mode='STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION'",
                        )
                        .execute(&mut *connection)
                        .await?;
                    } else {
                        for statement in [
                            "PRAGMA foreign_keys=ON",
                            "PRAGMA journal_mode=WAL",
                            "PRAGMA synchronous=FULL",
                            "PRAGMA busy_timeout=10000",
                        ] {
                            sqlx::query(statement).execute(&mut *connection).await?;
                        }
                    }
                    Ok(())
                })
            })
            .connect_with(options)
            .await?;
        let database = Arc::new(Self {
            pool,
            mysql,
            data_dir: settings.data_dir.clone(),
            writer: Arc::new(Mutex::new(())),
            cleanup_time: Mutex::new(None),
            timeout,
            lock_name: format!("nomi-auth:{}", &digest(&settings.mysql_database)[..48]),
        });
        let mut transaction = database.write().await?;
        schema::initialize(transaction.connection(), mysql).await?;
        transaction.commit().await?;
        Ok(database)
    }

    pub fn pool(&self) -> &AnyPool {
        &self.pool
    }
    pub fn is_mysql(&self) -> bool {
        self.mysql
    }
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub async fn write(&self) -> Result<WriteTransaction> {
        let guard = tokio::time::timeout(self.timeout, self.writer.clone().lock_owned())
            .await
            .map_err(|_| Error::problem("DATABASE_UNAVAILABLE", "Database writer is busy", 503))?;
        let mut connection = self.pool.acquire().await?;
        // Mark before any await: cancellation during GET_LOCK or BEGIN is also safe.
        connection.close_on_drop();
        if self.mysql {
            let record = sqlx::query("SELECT GET_LOCK(?, ?)")
                .bind(&self.lock_name)
                .bind(self.timeout.as_secs() as i64)
                .fetch_one(&mut *connection)
                .await?;
            if record.try_get::<Option<i64>, _>(0)? != Some(1) {
                return Err(Error::problem(
                    "DATABASE_UNAVAILABLE",
                    "Database writer is busy",
                    503,
                ));
            }
        }
        let begin = if self.mysql {
            "START TRANSACTION"
        } else {
            "BEGIN IMMEDIATE"
        };
        sqlx::query(begin).execute(&mut *connection).await?;
        Ok(WriteTransaction {
            connection,
            _guard: guard,
            mysql: self.mysql,
            lock_name: self.lock_name.clone(),
        })
    }

    pub async fn cleanup_if_due(&self, timestamp: i64) -> Result<()> {
        let mut previous = self.cleanup_time.lock().await;
        if previous.is_some_and(|time| (0..30).contains(&(timestamp - time))) {
            return Ok(());
        }
        self.cleanup(timestamp).await?;
        *previous = Some(timestamp);
        Ok(())
    }

    pub async fn cleanup(&self, timestamp: i64) -> Result<()> {
        let mut transaction = self.write().await?;
        for table in [
            "refresh_retries",
            "login_retries",
            "tokens",
            "joins",
            "registrations",
            "login_requests",
        ] {
            sqlx::query(&format!("DELETE FROM {table} WHERE expires_at<=?"))
                .bind(timestamp)
                .execute(transaction.connection())
                .await?;
        }
        for table in ["registrations", "login_requests"] {
            sqlx::query(&format!(
                "DELETE FROM {table} WHERE status='CANCELLED' OR session_issued=1"
            ))
            .execute(transaction.connection())
            .await?;
        }
        for table in ["receipts", "audit"] {
            sqlx::query(&format!("DELETE FROM {table} WHERE created_at<=?"))
                .bind(timestamp - 86400)
                .execute(transaction.connection())
                .await?;
        }
        transaction.commit().await
    }
}

impl WriteTransaction {
    pub fn connection(&mut self) -> &mut AnyConnection {
        &mut self.connection
    }

    pub async fn commit(mut self) -> Result<()> {
        sqlx::query("COMMIT").execute(&mut *self.connection).await?;
        if self.mysql {
            sqlx::query("SELECT RELEASE_LOCK(?)")
                .bind(&self.lock_name)
                .execute(&mut *self.connection)
                .await?;
        }
        Ok(())
    }
}

fn connection_url(settings: &Settings) -> Result<String> {
    if !settings.is_mysql() {
        return sqlite_url(&settings.data_dir.join("nomi-auth.sqlite3"), false);
    }
    let mut url = url::Url::parse("mysql://localhost").map_err(|_| Error::internal())?;
    url.set_host(Some(&settings.mysql_host))
        .map_err(|_| Error::internal())?;
    url.set_port(Some(settings.mysql_port))
        .map_err(|_| Error::internal())?;
    url.set_username(&settings.mysql_user)
        .map_err(|_| Error::internal())?;
    url.set_password(Some(&settings.mysql_password))
        .map_err(|_| Error::internal())?;
    url.set_path(&settings.mysql_database);
    let mut query = url.query_pairs_mut();
    query
        .append_pair("charset", "utf8mb4")
        .append_pair("collation", "utf8mb4_bin");
    if let Some(path) = &settings.mysql_unix_socket {
        query.append_pair("socket", &path.to_string_lossy());
    }
    if let Some(path) = &settings.mysql_ssl_ca {
        query
            .append_pair("ssl-mode", "VERIFY_IDENTITY")
            .append_pair("ssl-ca", &path.to_string_lossy());
    } else {
        query.append_pair("ssl-mode", "DISABLED");
    }
    drop(query);
    Ok(url.to_string())
}

pub(crate) fn sqlite_url(path: &Path, readonly: bool) -> Result<String> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let file_url = url::Url::from_file_path(&absolute).map_err(|_| Error::internal())?;
    // An opaque SQLite URL keeps the Windows drive colon out of the URL authority.
    #[cfg(windows)]
    let encoded_path = file_url.path().strip_prefix('/').unwrap_or(file_url.path());
    #[cfg(not(windows))]
    let encoded_path = file_url.path();
    Ok(format!(
        "sqlite:{encoded_path}?mode={}",
        if readonly { "ro" } else { "rwc" }
    ))
}

async fn check_sqlite_file(path: &Path) -> Result<()> {
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(&sqlite_url(path, true)?)
        .await?;
    let result = async {
        let mut connection = pool.acquire().await?;
        schema::check_version(&mut connection, false)
            .await
            .map(|_| ())
    }
    .await;
    pool.close().await;
    result
}

fn create_data_directory(path: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    // Existing deployment permissions are preserved; only new directories use this mode.
    builder.create(path)?;
    Ok(())
}
