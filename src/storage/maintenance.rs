use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use rsa::{RsaPrivateKey, pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey};
use sha2::{Digest, Sha256};
use sqlx::Row;

pub use super::transfer::import_sqlite;
use super::{Database, database::sqlite_url, transfer::export_sqlite};
use crate::core::{Error, Result};

/// Keep referenced skins and recently retired files, including interrupted uploads.
pub async fn cleanup_textures(
    database: &Database,
    timestamp: i64,
    retention: i64,
) -> Result<usize> {
    let mut transaction = database.write().await?;
    let referenced: HashSet<String> =
        sqlx::query("SELECT skin_hash FROM profiles WHERE skin_hash IS NOT NULL")
            .fetch_all(transaction.connection())
            .await?
            .iter()
            .map(|record| record.try_get(0))
            .collect::<std::result::Result<_, _>>()?;
    let directory = database.data_dir().join("textures");
    let mut removed = 0;
    if directory.is_dir() {
        for item in fs::read_dir(directory)? {
            let item = item?;
            let metadata = item.path().symlink_metadata()?;
            let name = item.file_name().to_string_lossy().into_owned();
            if !metadata.is_file() || referenced.contains(&name) {
                continue;
            }
            let modified = metadata
                .modified()?
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            if modified <= timestamp - retention {
                fs::remove_file(item.path())?;
                removed += 1;
            }
        }
    }
    transaction.commit().await?;
    Ok(removed)
}

/// Validate the complete snapshot before publishing any restored directory.
pub async fn validate_snapshot(directory: &Path) -> Result<()> {
    let database_path = directory.join("nomi-auth.sqlite3");
    if !database_path.is_file() {
        return Err(snapshot_error("Snapshot is missing its database"));
    }
    let key = fs::read_to_string(directory.join("texture-signing.pem"))?;
    RsaPrivateKey::from_pkcs8_pem(&key)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&key))
        .map_err(|_| snapshot_error("Snapshot signing key must be an unencrypted RSA key"))?;

    sqlx::any::install_default_drivers();
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect(&sqlite_url(&database_path, true)?)
        .await?;
    let result = async {
        let integrity: String = sqlx::query("PRAGMA integrity_check")
            .fetch_one(&pool)
            .await?
            .try_get(0)?;
        let invalid_reference = sqlx::query("PRAGMA foreign_key_check")
            .fetch_optional(&pool)
            .await?
            .is_some();
        if integrity != "ok" || invalid_reference {
            return Err(snapshot_error("Snapshot database is corrupt"));
        }
        for record in
            sqlx::query("SELECT DISTINCT skin_hash FROM profiles WHERE skin_hash IS NOT NULL")
                .fetch_all(&pool)
                .await?
        {
            let name: String = record.try_get(0)?;
            validate_texture(&directory.join("textures"), &name)?;
        }
        Ok(())
    }
    .await;
    pool.close().await;
    result
}

/// Back up database, referenced skins and signing key under one shared writer lock.
pub async fn backup_data(database: &Database, destination: &Path) -> Result<()> {
    if let Some(parent) = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let staging = tempfile::tempdir()?;
    let root = staging.path();
    fs::create_dir(root.join("textures"))?;

    let mut transaction = database.write().await?;
    export_sqlite(transaction.connection(), &root.join("nomi-auth.sqlite3")).await?;
    fs::copy(
        database.data_dir().join("texture-signing.pem"),
        root.join("texture-signing.pem"),
    )?;
    let referenced =
        sqlx::query("SELECT DISTINCT skin_hash FROM profiles WHERE skin_hash IS NOT NULL")
            .fetch_all(transaction.connection())
            .await?;
    for record in referenced {
        let name: String = record.try_get(0)?;
        validate_texture(&database.data_dir().join("textures"), &name)?;
        fs::copy(
            database.data_dir().join("textures").join(&name),
            root.join("textures").join(name),
        )?;
    }
    transaction.commit().await?;
    validate_snapshot(root).await?;

    // Exclusive creation never truncates an earlier backup, including a racing writer.
    let output = create_private_file(destination)?;
    let result = write_archive(output, root);
    if result.is_err() {
        fs::remove_file(destination)?;
    }
    result
}

pub async fn restore_data(archive_path: &Path, destination: &Path) -> Result<()> {
    if destination.symlink_metadata().is_ok() {
        return Err(snapshot_error("Restore destination must not exist"));
    }
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let staging = tempfile::Builder::new()
        .prefix(".nomi-restore-")
        .tempdir_in(parent)?;
    let root = staging.path().join("data");
    create_private_directory(&root)?;
    fs::create_dir(root.join("textures"))?;
    extract_archive(archive_path, &root)?;
    validate_snapshot(&root).await?;

    // Reserve the new directory atomically so another restore cannot overwrite it.
    create_private_directory(destination)?;
    let result = publish_restored(&root, destination);
    if result.is_err() {
        fs::remove_dir_all(destination)?;
    }
    result
}

fn write_archive(output: File, root: &Path) -> Result<()> {
    let compressed = GzEncoder::new(output, Compression::default());
    let mut archive = tar::Builder::new(compressed);
    let mut files = vec![
        PathBuf::from("nomi-auth.sqlite3"),
        PathBuf::from("texture-signing.pem"),
    ];
    for entry in fs::read_dir(root.join("textures"))? {
        files.push(PathBuf::from("textures").join(entry?.file_name()));
    }
    files.sort();
    for path in files {
        archive.append_path_with_name(root.join(&path), &path)?;
    }
    let output = archive.into_inner()?.finish()?;
    output.sync_all()?;
    Ok(())
}

fn extract_archive(archive_path: &Path, root: &Path) -> Result<()> {
    let mut archive = tar::Archive::new(GzDecoder::new(File::open(archive_path)?));
    let mut seen = HashSet::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let name = entry.path()?.to_string_lossy().replace('\\', "/");
        if !entry.header().entry_type().is_file()
            || !valid_entry(&name)
            || !seen.insert(name.clone())
        {
            return Err(snapshot_error(
                "Unexpected, duplicate or unsafe backup entry",
            ));
        }
        if name.starts_with("textures/") && entry.size() > 1024 * 1024 {
            return Err(snapshot_error("Snapshot texture exceeds the size limit"));
        }
        let mut output = create_private_file(&root.join(name))?;
        io::copy(&mut entry, &mut output)?;
    }
    Ok(())
}

fn publish_restored(root: &Path, destination: &Path) -> Result<()> {
    fs::create_dir(destination.join("textures"))?;
    for name in ["nomi-auth.sqlite3", "texture-signing.pem"] {
        fs::rename(root.join(name), destination.join(name))?;
    }
    for entry in fs::read_dir(root.join("textures"))? {
        let entry = entry?;
        fs::rename(
            entry.path(),
            destination.join("textures").join(entry.file_name()),
        )?;
    }
    Ok(())
}

fn validate_texture(directory: &Path, name: &str) -> Result<()> {
    if !valid_hash(name) {
        return Err(snapshot_error("Invalid texture reference"));
    }
    let path = directory.join(name);
    let metadata = path.metadata()?;
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err(snapshot_error(
            "Snapshot is missing a valid referenced texture",
        ));
    }
    let digest = hex::encode(Sha256::digest(fs::read(path)?));
    if digest != name {
        return Err(snapshot_error("Snapshot contains a corrupt texture"));
    }
    Ok(())
}

fn valid_hash(name: &str) -> bool {
    name.len() == 64
        && name
            .bytes()
            .all(|letter| letter.is_ascii_digit() || (b'a'..=b'f').contains(&letter))
}

fn valid_entry(name: &str) -> bool {
    matches!(name, "nomi-auth.sqlite3" | "texture-signing.pem")
        || name.strip_prefix("textures/").is_some_and(valid_hash)
}

fn create_private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn create_private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    let options = {
        use std::os::unix::fs::DirBuilderExt;
        let mut options = fs::DirBuilder::new();
        options.mode(0o700);
        options
    };
    #[cfg(not(unix))]
    let options = fs::DirBuilder::new();
    options.create(path)?;
    Ok(())
}

fn snapshot_error(message: &str) -> Error {
    Error::problem("INVALID_SNAPSHOT", message, 500)
}
