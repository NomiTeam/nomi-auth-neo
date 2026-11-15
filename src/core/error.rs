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
    source: Option<sqlx::Error>,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn problem(code: &str, message: &str, status: u16) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            status,
            source: None,
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

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &dyn std::error::Error)
    }
}

impl From<sqlx::Error> for Error {
    fn from(source: sqlx::Error) -> Self {
        let mut error = Self::problem("DATABASE_UNAVAILABLE", "数据库暂时不可用，请重试", 503);
        error.source = Some(source);
        error
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn database_causes_are_available_to_operators_but_not_http_clients() {
        let error = Error::from(sqlx::Error::Protocol("private-driver-detail".into()));
        assert!(std::error::Error::source(&error).is_some());
        assert!(!error.to_string().contains("private-driver-detail"));
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("DATABASE_UNAVAILABLE"));
        assert!(!text.contains("private-driver-detail"));
    }
}
