use clap::{CommandFactory, Parser, Subcommand};
use nomi_auth_neo::{
    core::{Error, Settings, security::now},
    http::App,
    services::Auth,
    storage::{Database, maintenance},
};
use std::{net::SocketAddr, path::PathBuf};

#[derive(Parser)]
#[command(version, about = "Nomi passwordless authentication service")]
struct Arguments {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Start the authentication HTTP service.
    Serve {
        /// Local address to bind.
        #[arg(long, default_value = "127.0.0.1")]
        host: std::net::IpAddr,
        /// Local TCP port to listen on.
        #[arg(long, default_value_t = 8000)]
        port: u16,
    },
    /// Export a complete database, signing-key and skin snapshot.
    Backup {
        /// New archive file to create.
        destination: PathBuf,
    },
    /// Restore a snapshot into a new data directory.
    Restore {
        /// Snapshot archive to read.
        archive: PathBuf,
        /// New directory to create; existing directories are rejected.
        destination: PathBuf,
    },
    /// Remove expired temporary records and retired skins.
    Cleanup,
    /// Disable an account and revoke its active sessions.
    Disable {
        /// Account ID, matched without case sensitivity.
        login_name: String,
    },
    /// Re-enable a disabled account.
    Enable {
        /// Account ID, matched without case sensitivity.
        login_name: String,
    },
    /// Import a SQLite snapshot into an empty MySQL/MariaDB database.
    MigrateDatabase {
        /// Source nomi-auth.sqlite3 file; the source is not changed.
        source: PathBuf,
    },
    /// Approve a launcher code for a local account without a QQ binding.
    TestLogin {
        /// Unclaimed login code shown by the launcher.
        code: String,
        /// New or existing account ID without a QQ binding.
        name: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let arguments = Arguments::parse();
    let Some(command) = arguments.command else {
        Arguments::command().print_help()?;
        println!();
        return Ok(());
    };
    if let Command::Restore {
        archive,
        destination,
    } = &command
    {
        maintenance::restore_data(archive, destination).await?;
        println!("Restored data directory: {}", destination.display());
        return Ok(());
    }
    let generated = matches!(&command, Command::Serve { .. })
        && nomi_auth_neo::core::config::create_env(std::path::Path::new(".env"))?;
    if generated {
        println!(
            "Created .env with default settings and a random bot secret. Edit .env, then run the program again."
        );
        return Ok(());
    }
    let settings = Settings::from_env()?;
    match command {
        Command::Serve { host, port } => serve(settings, SocketAddr::new(host, port)).await?,
        command => maintain(settings, command).await?,
    }
    Ok(())
}

async fn serve(settings: Settings, address: SocketAddr) -> anyhow::Result<()> {
    let app = App::new(settings).await?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(address = %listener.local_addr()?, "Authentication service listening");
    let cleanup = app.start_cleanup();
    let result = axum::serve(
        listener,
        app.router()
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await;
    cleanup.abort();
    result?;
    Ok(())
}

async fn maintain(settings: Settings, command: Command) -> anyhow::Result<()> {
    let database = Database::open(&settings).await?;
    match command {
        Command::Backup { destination } => {
            maintenance::backup_data(&database, &destination).await?;
            println!("Complete data snapshot: {}", destination.display());
        }
        Command::Cleanup => {
            database.cleanup(now()).await?;
            maintenance::cleanup_textures(&database, now(), 86400).await?;
            println!("Expired transient data deleted; receipts and audit retained for one day.");
        }
        Command::MigrateDatabase { source } => {
            maintenance::import_sqlite(&source, &database).await?;
            println!("Migration verified; source unchanged.");
        }
        Command::TestLogin { code, name } => {
            let auth = Auth::new(std::sync::Arc::new(settings), database.clone());
            let profile = auth.test_login(&code, &name).await?;
            println!("Test login approved: {} ({})", profile.name, profile.uuid);
        }
        Command::Disable { login_name } => set_account(&database, &login_name, false).await?,
        Command::Enable { login_name } => set_account(&database, &login_name, true).await?,
        Command::Serve { .. } | Command::Restore { .. } => {
            unreachable!("Handled before maintenance")
        }
    }
    Ok(())
}

async fn set_account(database: &Database, login_name: &str, enabled: bool) -> anyhow::Result<()> {
    let mut transaction = database.write().await?;
    let account_id: Option<String> =
        sqlx::query_scalar("SELECT id FROM accounts WHERE login_normalized=?")
            .bind(login_name.to_lowercase())
            .fetch_optional(transaction.connection())
            .await?;
    let account_id =
        account_id.ok_or_else(|| Error::problem("ACCOUNT_NOT_FOUND", "Account not found", 404))?;
    let status = if enabled { "active" } else { "disabled" };
    let action = if enabled { "enable" } else { "disable" };
    sqlx::query("UPDATE accounts SET status=? WHERE id=?")
        .bind(status)
        .bind(&account_id)
        .execute(transaction.connection())
        .await?;
    sqlx::query("DELETE FROM tokens WHERE account_id=?")
        .bind(&account_id)
        .execute(transaction.connection())
        .await?;
    sqlx::query(
        "DELETE FROM joins WHERE profile_id IN (SELECT uuid FROM profiles WHERE account_id=?)",
    )
    .bind(&account_id)
    .execute(transaction.connection())
    .await?;
    sqlx::query("INSERT INTO audit(action,account_id,created_at) VALUES(?,?,?)")
        .bind(action)
        .bind(&account_id)
        .bind(now())
        .execute(transaction.connection())
        .await?;
    transaction.commit().await?;
    println!("Account {login_name}: {status}");
    Ok(())
}

async fn shutdown() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
