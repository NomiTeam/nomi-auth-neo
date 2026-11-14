use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

/// A safe protocol error. Driver details and credentials never enter responses.
#[derive(Debug)]
pub struct Error {
    pub code: String,
    pub message: String,
    pub status: u16,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn problem(code: &str, message: &str, status: u16) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            status,
        }
    }

    pub fn invalid() -> Self {
        Self::problem("INVALID_REQUEST", "请求格式或参数不符合要求", 422)
    }

    pub fn internal() -> Self {
        Self::problem("SERVICE_UNAVAILABLE", "账号服务暂时不可用，请重试", 503)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

impl From<sqlx::Error> for Error {
    fn from(_: sqlx::Error) -> Self {
        Self::problem("DATABASE_UNAVAILABLE", "数据库暂时不可用，请重试", 503)
    }
}

impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::internal()
    }
}

impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self::invalid()
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(json!({"code":self.code,"message":self.message,"request_id":uuid::Uuid::new_v4().simple().to_string()}))).into_response()
    }
}
