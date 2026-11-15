use std::{
    io::{Cursor, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    body::Body,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use image::{ImageFormat, ImageReader, Limits};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::AnyConnection;

use super::{Account, Auth, game::normalize_uuid};
use crate::{
    core::{Error, Reply, Request, Result, Settings},
    storage::Database,
};

/// Skin publication shares the SQL writer lock with backups and orphan cleanup.
#[derive(Clone)]
pub struct SkinService {
    settings: Arc<Settings>,
    database: Arc<Database>,
    auth: Auth,
    directory: PathBuf,
}

struct UploadTarget {
    kind: &'static str,
    profile_id: Option<String>,
}

impl SkinService {
    pub fn new(settings: Arc<Settings>, database: Arc<Database>, auth: Auth) -> Self {
        let directory = settings.data_dir.join("textures");
        Self {
            settings,
            database,
            auth,
            directory,
        }
    }

    pub async fn upload(&self, request: &Request, image: Vec<u8>, model: &str) -> Result<Reply> {
        let target = upload_target(&request.path)?;
        {
            let mut connection = self.database.pool().acquire().await?;
            self.check_account(&mut connection, request, &target)
                .await?;
        }
        let model = if model.is_empty() { "default" } else { model };
        if !matches!(model, "default" | "slim") {
            return Err(Error::problem("INVALID_MODEL", "不支持的手臂模型", 400));
        }
        let (content, texture_hash) = tokio::task::spawn_blocking(move || decode_skin(&image))
            .await
            .map_err(|_| Error::internal())??;

        let mut transaction = self.database.write().await?;
        let account = self
            .check_account(transaction.connection(), request, &target)
            .await?;
        let profile = self
            .auth
            .profile(transaction.connection(), &account.id)
            .await?;
        self.publish(content, &texture_hash).await?;
        if profile.skin_hash.as_deref() != Some(texture_hash.as_str()) {
            self.retire(profile.skin_hash.as_deref()).await?;
        }
        sqlx::query("UPDATE profiles SET skin_hash=?,skin_model=? WHERE account_id=?")
            .bind(&texture_hash)
            .bind(model)
            .bind(&account.id)
            .execute(transaction.connection())
            .await?;
        sqlx::query(
            "INSERT INTO audit(action,account_id,detail,created_at) VALUES('skin_upload',?,?,?)",
        )
        .bind(&account.id)
        .bind(&texture_hash)
        .bind(crate::core::security::now())
        .execute(transaction.connection())
        .await?;
        transaction.commit().await?;

        if target.kind == "game" {
            return Ok(Reply::empty(204));
        }
        let url = format!(
            "{}/textures/{texture_hash}",
            self.settings.public_url.trim_end_matches('/')
        );
        Ok(Reply::ok(json!({"hash":texture_hash,"url":url})))
    }

    async fn check_account(
        &self,
        connection: &mut AnyConnection,
        request: &Request,
        target: &UploadTarget,
    ) -> Result<Account> {
        let account = self
            .auth
            .account_for_token(connection, request.bearer()?, target.kind)
            .await?;
        if let Some(expected) = &target.profile_id {
            let profile = self.auth.profile(connection, &account.id).await?;
            if profile.uuid != *expected {
                return Err(Error::problem(
                    "INVALID_PROFILE",
                    "无法修改此角色的皮肤",
                    403,
                ));
            }
        }
        Ok(account)
    }

    async fn publish(&self, content: Vec<u8>, texture_hash: &str) -> Result<()> {
        let directory = self.directory.clone();
        let texture_hash = texture_hash.to_owned();
        tokio::task::spawn_blocking(move || publish_skin(&directory, &texture_hash, &content))
            .await
            .map_err(|_| Error::internal())?
    }

    async fn retire(&self, texture_hash: Option<&str>) -> Result<()> {
        retire_texture(&self.directory, texture_hash).await
    }

    pub async fn clear(&self, request: &Request) -> Result<Reply> {
        let mut transaction = self.database.write().await?;
        let account = self
            .auth
            .account_for_token(transaction.connection(), request.bearer()?, "management")
            .await?;
        let profile = self
            .auth
            .profile(transaction.connection(), &account.id)
            .await?;
        self.retire(profile.skin_hash.as_deref()).await?;
        sqlx::query("UPDATE profiles SET skin_hash=NULL WHERE account_id=?")
            .bind(&account.id)
            .execute(transaction.connection())
            .await?;
        transaction.commit().await?;
        Ok(Reply::empty(204))
    }

    pub async fn texture(&self, texture_hash: &str) -> Result<Response> {
        if !valid_hash(texture_hash) {
            return Err(texture_missing());
        }
        let path = self.directory.join(texture_hash);
        let metadata = tokio::fs::symlink_metadata(&path)
            .await
            .map_err(|_| texture_missing())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(texture_missing());
        }
        let content = tokio::fs::read(path).await.map_err(|_| texture_missing())?;
        Ok((
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "image/png"),
                (header::CACHE_CONTROL, "public,max-age=31536000,immutable"),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            ],
            Body::from(content),
        )
            .into_response())
    }
}

/// Keep retired files briefly so uploads can safely reuse content-addressed skins.
pub(crate) async fn retire_texture(directory: &Path, texture_hash: Option<&str>) -> Result<()> {
    let Some(texture_hash) = texture_hash.filter(|value| valid_hash(value)) else {
        return Ok(());
    };
    let path = directory.join(texture_hash);
    tokio::task::spawn_blocking(move || {
        if path.is_file() {
            filetime::set_file_mtime(path, filetime::FileTime::now())?;
        }
        Ok(())
    })
    .await
    .map_err(|_| Error::internal())?
}

fn upload_target(path: &str) -> Result<UploadTarget> {
    if path == "/api/v1/me/profile/skin" {
        return Ok(UploadTarget {
            kind: "management",
            profile_id: None,
        });
    }
    let profile_id = path
        .strip_prefix("/api/yggdrasil/api/user/profile/")
        .and_then(|value| value.strip_suffix("/skin"))
        .ok_or_else(|| Error::problem("NOT_FOUND", "Not Found", 404))?;
    let profile_id = normalize_uuid(profile_id)
        .ok_or_else(|| Error::problem("INVALID_PROFILE", "角色 UUID 无效", 400))?;
    Ok(UploadTarget {
        kind: "game",
        profile_id: Some(profile_id),
    })
}

fn decode_skin(content: &[u8]) -> Result<(Vec<u8>, String)> {
    if content.len() > 1024 * 1024 {
        return Err(Error::problem("INVALID_IMAGE", "图片不能超过 1 MiB", 413));
    }
    let mut reader = ImageReader::new(Cursor::new(content))
        .with_guessed_format()
        .map_err(|_| invalid_image())?;
    if reader.format() != Some(ImageFormat::Png) {
        return Err(invalid_image());
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(64);
    limits.max_image_height = Some(64);
    limits.max_alloc = Some(1024 * 1024);
    reader.limits(limits);
    let image = reader.decode().map_err(|_| invalid_image())?;
    if image.width() != 64 || !matches!(image.height(), 32 | 64) {
        return Err(invalid_image());
    }

    // Re-encoding strips caller-controlled PNG chunks before publishing the file.
    let image = image::DynamicImage::ImageRgba8(image.to_rgba8());
    let mut output = Cursor::new(Vec::new());
    image
        .write_to(&mut output, ImageFormat::Png)
        .map_err(|_| invalid_image())?;
    let content = output.into_inner();
    let texture_hash = hex::encode(Sha256::digest(&content));
    Ok((content, texture_hash))
}

fn publish_skin(directory: &Path, texture_hash: &str, content: &[u8]) -> Result<()> {
    std::fs::create_dir_all(directory)?;
    let target = directory.join(texture_hash);
    if target.exists() {
        return Ok(());
    }
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    temporary.write_all(content)?;
    temporary.as_file().sync_all()?;
    if let Err(error) = temporary.persist_noclobber(target)
        && error.error.kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err(error.error.into());
    }
    Ok(())
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|letter| letter.is_ascii_digit() || (b'a'..=b'f').contains(&letter))
}

fn texture_missing() -> Error {
    Error::problem("NOT_FOUND", "材质不存在", 404)
}
fn invalid_image() -> Error {
    Error::problem("INVALID_IMAGE", "只接受 64x64 或 64x32 PNG", 400)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(width: u32, height: u32) -> Vec<u8> {
        let mut output = Cursor::new(Vec::new());
        image::DynamicImage::new_rgba8(width, height)
            .write_to(&mut output, ImageFormat::Png)
            .unwrap();
        output.into_inner()
    }

    #[test]
    fn images_are_validated_and_content_addressed() {
        for height in [32, 64] {
            let (content, hash) = decode_skin(&png(64, height)).unwrap();
            assert_eq!(hex::encode(Sha256::digest(&content)), hash);
            assert_eq!(image::load_from_memory(&content).unwrap().height(), height);
        }
        for content in [png(32, 32), png(65, 64), b"invalid".to_vec()] {
            assert!(decode_skin(&content).is_err());
        }
        assert_eq!(
            decode_skin(&vec![0; 1024 * 1024 + 1]).unwrap_err().status,
            413
        );
    }

    #[test]
    fn publication_is_complete_and_preserves_existing_files() {
        let directory = tempfile::tempdir().unwrap();
        let (content, hash) = decode_skin(&png(64, 64)).unwrap();
        publish_skin(directory.path(), &hash, &content).unwrap();
        publish_skin(directory.path(), &hash, b"must not overwrite").unwrap();
        assert_eq!(std::fs::read(directory.path().join(hash)).unwrap(), content);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn profile_paths_and_hashes_reject_traversal() {
        assert!(!valid_hash("../texture-signing.pem"));
        assert!(!valid_hash(&"A".repeat(64)));
        assert!(upload_target("/api/yggdrasil/api/user/profile/not-a-uuid/skin").is_err());
    }
}
