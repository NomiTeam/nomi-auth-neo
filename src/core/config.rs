use super::{Error, Result};
use std::{collections::HashMap, env, path::PathBuf, str::FromStr};

/// Configuration uses the existing NOMI_* names. Never derive Debug for secrets.
#[derive(Clone)]
pub struct Settings {
    pub public_url: String,
    pub data_dir: PathBuf,
    pub bot_token: String,
    pub bot_app_id: String,
    pub group_openid: String,
    pub group_label: String,
    pub registration_ttl: i64,
    pub rename_cooldown: i64,
    pub game_token_ttl: i64,
    pub refresh_token_ttl: i64,
    pub management_token_ttl: i64,
    pub database_backend: String,
    pub mysql_host: String,
    pub mysql_port: u16,
    pub mysql_database: String,
    pub mysql_user: String,
    pub mysql_password: String,
    pub mysql_unix_socket: Option<PathBuf>,
    pub mysql_ssl_ca: Option<PathBuf>,
    pub database_timeout: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            public_url: "http://127.0.0.1:8000".into(),
            data_dir: "data".into(),
            bot_token: String::new(),
            bot_app_id: String::new(),
            group_openid: String::new(),
            group_label: "Server Group".into(),
            registration_ttl: 300,
            rename_cooldown: 604800,
            game_token_ttl: 86400,
            refresh_token_ttl: 2592000,
            management_token_ttl: 3600,
            database_backend: "sqlite".into(),
            mysql_host: "127.0.0.1".into(),
            mysql_port: 3306,
            mysql_database: "nomi_auth".into(),
            mysql_user: "nomi_auth".into(),
            mysql_password: String::new(),
            mysql_unix_socket: None,
            mysql_ssl_ca: None,
            database_timeout: 10,
        }
    }
}

impl Settings {
    pub fn from_env() -> Result<Self> {
        let values = load_values()?;
        Self::from_values(&values)
    }

    fn from_values(values: &HashMap<String, String>) -> Result<Self> {
        let defaults = Self::default();
        let settings = Self {
            public_url: read(values, "PUBLIC_URL", defaults.public_url)?,
            data_dir: read(values, "DATA_DIR", defaults.data_dir)?,
            bot_token: read(values, "BOT_TOKEN", defaults.bot_token)?,
            bot_app_id: read(values, "BOT_APP_ID", defaults.bot_app_id)?,
            group_openid: read(values, "GROUP_OPENID", defaults.group_openid)?,
            group_label: read(values, "GROUP_LABEL", defaults.group_label)?,
            registration_ttl: read(values, "REGISTRATION_TTL", defaults.registration_ttl)?,
            rename_cooldown: read(values, "RENAME_COOLDOWN", defaults.rename_cooldown)?,
            game_token_ttl: read(values, "GAME_TOKEN_TTL", defaults.game_token_ttl)?,
            refresh_token_ttl: read(values, "REFRESH_TOKEN_TTL", defaults.refresh_token_ttl)?,
            management_token_ttl: read(
                values,
                "MANAGEMENT_TOKEN_TTL",
                defaults.management_token_ttl,
            )?,
            database_backend: read(values, "DATABASE_BACKEND", defaults.database_backend)?,
            mysql_host: read(values, "MYSQL_HOST", defaults.mysql_host)?,
            mysql_port: read(values, "MYSQL_PORT", defaults.mysql_port)?,
            mysql_database: read(values, "MYSQL_DATABASE", defaults.mysql_database)?,
            mysql_user: read(values, "MYSQL_USER", defaults.mysql_user)?,
            mysql_password: read(values, "MYSQL_PASSWORD", defaults.mysql_password)?,
            mysql_unix_socket: optional_path(values, "MYSQL_UNIX_SOCKET"),
            mysql_ssl_ca: optional_path(values, "MYSQL_SSL_CA"),
            database_timeout: read(values, "DATABASE_TIMEOUT", defaults.database_timeout)?,
        };
        settings.validate()?;
        Ok(settings)
    }

    pub fn is_mysql(&self) -> bool {
        self.database_backend != "sqlite"
    }

    pub fn validate(&self) -> Result<()> {
        let address = url::Url::parse(&self.public_url).ok();
        let valid_address = address.is_some_and(|address| {
            matches!(address.scheme(), "http" | "https")
                && address.host_str().is_some()
                && address.username().is_empty()
                && address.password().is_none()
                && address.query().is_none()
                && address.fragment().is_none()
                && self.public_url.trim() == self.public_url
        });
        let timestamp = super::security::now();
        let valid = matches!(
            self.database_backend.as_str(),
            "sqlite" | "mysql" | "mariadb"
        ) && valid_address
            && self.bot_token.len() >= 32
            && self.bot_token.bytes().all(|byte| byte.is_ascii_graphic())
            && (1..=128).contains(&self.bot_app_id.chars().count())
            && (1..=128).contains(&self.group_openid.chars().count())
            && [
                self.rename_cooldown,
                self.game_token_ttl,
                self.refresh_token_ttl,
                self.management_token_ttl,
            ]
            .into_iter()
            .all(|value| timestamp.checked_add(value).is_some())
            && (30..=1800).contains(&self.registration_ttl)
            && self.rename_cooldown >= 0
            && self.game_token_ttl >= 60
            && self.refresh_token_ttl >= 60
            && self.management_token_ttl >= 60
            && (1..=120).contains(&self.database_timeout)
            && self.mysql_port > 0
            && (!self.is_mysql()
                || (!self.mysql_database.is_empty() && !self.mysql_user.is_empty()));
        if !valid {
            return Err(Error::problem(
                "INVALID_CONFIG",
                "Invalid or missing Nomi configuration",
                500,
            ));
        }
        Ok(())
    }
}

/// Publish a private initial configuration without replacing an existing file.
pub fn create_env(path: &std::path::Path) -> std::io::Result<bool> {
    use std::io::Write;
    match std::fs::symlink_metadata(path) {
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let configuration = format!(
        r#"NOMI_PUBLIC_URL=http://127.0.0.1:8000
NOMI_DATA_DIR=./data
NOMI_BOT_TOKEN={bot_token}
NOMI_BOT_APP_ID=
NOMI_GROUP_OPENID=
NOMI_GROUP_LABEL=Server Group
NOMI_REGISTRATION_TTL=300
NOMI_RENAME_COOLDOWN=604800
NOMI_GAME_TOKEN_TTL=86400
NOMI_REFRESH_TOKEN_TTL=2592000
NOMI_MANAGEMENT_TOKEN_TTL=3600

# sqlite (default), mysql, or mariadb
NOMI_DATABASE_BACKEND=sqlite
NOMI_MYSQL_HOST=127.0.0.1
NOMI_MYSQL_PORT=3306
NOMI_MYSQL_DATABASE=nomi_auth
NOMI_MYSQL_USER=nomi_auth
NOMI_MYSQL_PASSWORD=
# NOMI_MYSQL_UNIX_SOCKET=/run/mysqld/mysqld.sock
# NOMI_MYSQL_SSL_CA=/path/to/ca.pem
NOMI_DATABASE_TIMEOUT=10
"#,
        bot_token = super::security::secret(),
    );
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    temporary.write_all(configuration.as_bytes())?;
    temporary.as_file().sync_all()?;
    match temporary.persist_noclobber(path) {
        Ok(_) => Ok(true),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error.error),
    }
}

fn read<T: FromStr>(values: &HashMap<String, String>, name: &str, default: T) -> Result<T> {
    match values.get(&format!("NOMI_{name}")) {
        Some(value) => value
            .parse()
            .or_else(|_| value.trim().parse())
            .map_err(|_| Error::problem("INVALID_CONFIG", &format!("Invalid NOMI_{name}"), 500)),
        None => Ok(default),
    }
}

fn optional_path(values: &HashMap<String, String>, name: &str) -> Option<PathBuf> {
    values
        .get(&format!("NOMI_{name}"))
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn load_values() -> Result<HashMap<String, String>> {
    let mut values = HashMap::new();
    // Read only this application's file; a parent project must not supply credentials.
    match dotenvy::from_path_iter(".env") {
        Ok(entries) => {
            for entry in entries {
                let (name, value) = entry
                    .map_err(|_| Error::problem("INVALID_CONFIG", "Invalid .env file", 500))?;
                values.insert(name.to_ascii_uppercase(), value);
            }
        }
        Err(dotenvy::Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => {
            return Err(Error::problem(
                "INVALID_CONFIG",
                "Cannot read .env file",
                500,
            ));
        }
    }
    // Environment values take precedence, including case-insensitive legacy names.
    for (name, value) in env::vars_os() {
        if let (Some(name), Some(value)) = (name.to_str(), value.to_str()) {
            values.insert(name.to_ascii_uppercase(), value.to_owned());
        }
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_database_selection_are_validated() {
        let mut values = HashMap::from([
            ("NOMI_BOT_TOKEN".into(), "x".repeat(32)),
            ("NOMI_BOT_APP_ID".into(), "app".into()),
            ("NOMI_GROUP_OPENID".into(), "group".into()),
        ]);
        let settings = Settings::from_values(&values).unwrap();
        assert_eq!(settings.database_backend, "sqlite");
        assert_eq!(settings.registration_ttl, 300);
        values.insert("NOMI_DATABASE_BACKEND".into(), "mariadb".into());
        assert!(Settings::from_values(&values).unwrap().is_mysql());
        values.insert("NOMI_DATABASE_BACKEND".into(), "unknown".into());
        assert!(Settings::from_values(&values).is_err());
    }
    #[test]
    fn invalid_public_urls_and_overflowing_lifetimes_are_rejected() {
        let base = Settings {
            bot_token: "x".repeat(32),
            bot_app_id: "app".into(),
            group_openid: "group".into(),
            ..Settings::default()
        };
        for address in [
            "",
            "missing-scheme",
            "ftp://auth.test",
            "https://user:password@auth.test",
            "https://auth.test?query",
            "https://auth.test#fragment",
        ] {
            let settings = Settings {
                public_url: address.into(),
                ..base.clone()
            };
            assert!(settings.validate().is_err(), "accepted {address}");
        }
        for settings in [
            Settings {
                game_token_ttl: i64::MAX,
                ..base.clone()
            },
            Settings {
                refresh_token_ttl: i64::MAX,
                ..base.clone()
            },
            Settings {
                management_token_ttl: i64::MAX,
                ..base.clone()
            },
            Settings {
                rename_cooldown: i64::MAX,
                ..base.clone()
            },
            Settings {
                bot_token: "密".repeat(32),
                ..base.clone()
            },
            Settings {
                group_openid: "x".repeat(129),
                ..base.clone()
            },
        ] {
            assert!(settings.validate().is_err());
        }
    }
}
