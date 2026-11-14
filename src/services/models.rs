use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::{Error, Result};

/// Optional token attributes are grouped so issuance calls remain readable.
#[derive(Clone, Copy, Default)]
pub struct TokenOptions<'a> {
    pub client_token: Option<&'a str>,
    pub value: Option<&'a str>,
    pub issued_at: Option<i64>,
}

#[derive(Clone, sqlx::FromRow)]
pub struct Account {
    pub id: String,
    pub login_name: String,
    pub status: String,
}

#[derive(Clone, Serialize, sqlx::FromRow)]
pub struct Profile {
    pub uuid: String,
    pub account_id: String,
    pub name: String,
    pub name_normalized: String,
    pub skin_hash: Option<String>,
    pub skin_model: String,
    pub last_renamed_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
pub(crate) struct Token {
    pub account_id: String,
    pub client_token: Option<String>,
}

#[derive(sqlx::FromRow)]
pub(crate) struct LoginRecord {
    pub id: String,
    pub poll_hash: String,
    pub account_id: Option<String>,
    pub status: String,
    pub expires_at: i64,
    pub session_issued: i64,
    pub app_id: Option<String>,
    pub group_id: Option<String>,
    pub member_id: Option<String>,
    pub error: Option<String>,
}

#[derive(sqlx::FromRow)]
pub(crate) struct RegistrationRecord {
    pub id: String,
    pub poll_hash: String,
    pub name: String,
    pub status: String,
    pub expires_at: i64,
    pub account_id: Option<String>,
    pub session_issued: i64,
    pub error: Option<String>,
}

pub(crate) struct SessionClaim<'a> {
    pub id: &'a str,
    pub account_id: Option<&'a str>,
    pub status: &'a str,
    pub expires_at: i64,
    pub session_issued: i64,
    pub table: &'static str,
    pub required_status: &'static str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EmptyRequest {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NameRequest {
    pub name: String,
}

/// Field order deliberately matches Pydantic's model_dump_json, including Unicode.
#[derive(Deserialize, Serialize)]
pub(crate) struct Redemption {
    pub code: String,
    pub bot_app_id: String,
    pub group_openid: String,
    pub member_openid: String,
    pub event_id: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct MemberOperation {
    pub bot_app_id: String,
    pub group_openid: String,
    pub member_openid: String,
    pub event_id: String,
    pub name: String,
}

pub(crate) trait Event: Serialize {
    fn app_id(&self) -> &str;
    fn group_id(&self) -> &str;
    fn member_id(&self) -> &str;
    fn event_id(&self) -> &str;

    fn validate_identity(&self) -> Result<()> {
        for value in [self.app_id(), self.group_id(), self.member_id()] {
            if !bounded(value, 1, 128) {
                return Err(Error::invalid());
            }
        }
        if !bounded(self.event_id(), 1, 256) {
            return Err(Error::invalid());
        }
        Ok(())
    }

    fn payload_hash(&self) -> Result<String> {
        let canonical = serde_json::to_string(self)?;
        Ok(crate::core::security::digest(&canonical))
    }
}

macro_rules! event_identity {
    ($event:ty) => {
        impl Event for $event {
            fn app_id(&self) -> &str {
                &self.bot_app_id
            }
            fn group_id(&self) -> &str {
                &self.group_openid
            }
            fn member_id(&self) -> &str {
                &self.member_openid
            }
            fn event_id(&self) -> &str {
                &self.event_id
            }
        }
    };
}
event_identity!(Redemption);
event_identity!(MemberOperation);

impl Redemption {
    pub fn validate(&self) -> Result<()> {
        self.validate_identity()?;
        if !bounded(&self.code, 1, 64) {
            return Err(Error::invalid());
        }
        Ok(())
    }
}

impl MemberOperation {
    pub fn validate(&self) -> Result<()> {
        self.validate_identity()?;
        if !bounded(&self.name, 0, 64) {
            return Err(Error::invalid());
        }
        Ok(())
    }
}

pub(crate) fn bounded(value: &str, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.chars().count())
}

pub(crate) fn parse_result(value: &str) -> Result<Value> {
    serde_json::from_str(value).map_err(|_| Error::internal())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_serialization_preserves_python_field_order() {
        let event = Redemption {
            code: "ABCD-2345-EFGH".into(),
            bot_app_id: "app".into(),
            group_openid: "group".into(),
            member_openid: "member".into(),
            event_id: "event".into(),
        };
        assert_eq!(
            serde_json::to_string(&event).unwrap(),
            r#"{"code":"ABCD-2345-EFGH","bot_app_id":"app","group_openid":"group","member_openid":"member","event_id":"event"}"#
        );
        let named = MemberOperation {
            bot_app_id: "app".into(),
            group_openid: "group".into(),
            member_openid: "member".into(),
            event_id: "event".into(),
            name: "Alice".into(),
        };
        assert_eq!(
            serde_json::to_string(&named).unwrap(),
            r#"{"bot_app_id":"app","group_openid":"group","member_openid":"member","event_id":"event","name":"Alice"}"#
        );
    }
}
