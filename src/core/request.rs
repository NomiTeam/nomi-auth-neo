use super::{Error, Result};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::HashMap;

/// Transport data passed to the account managers without HTTP framework extractors.
#[derive(Clone, Default)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub authorization: Option<String>,
    pub request_id: Option<String>,
    pub body: Value,
}

impl Request {
    pub fn parse<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_value(self.body.clone()).map_err(|_| Error::invalid())
    }

    pub fn bearer(&self) -> Result<&str> {
        bearer(self.authorization.as_deref())
    }
}

pub fn bearer(header: Option<&str>) -> Result<&str> {
    header
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| Error::problem("UNAUTHORIZED", "缺少有效凭证", 401))
}

pub struct Reply {
    pub status: u16,
    pub body: Option<Value>,
}

impl Reply {
    pub fn json(status: u16, body: Value) -> Self {
        Self {
            status,
            body: Some(body),
        }
    }
    pub fn ok(body: Value) -> Self {
        Self::json(200, body)
    }
    pub fn empty(status: u16) -> Self {
        Self { status, body: None }
    }
}

impl IntoResponse for Reply {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        match self.body {
            Some(body) => (status, Json(body)).into_response(),
            None => status.into_response(),
        }
    }
}
