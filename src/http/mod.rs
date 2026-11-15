mod routes;
mod runtime;

use crate::{
    core::{Error, Request, Result, Settings},
    services::{Auth, game::Game, skins::SkinService},
    storage::Database,
};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{FromRequest, Multipart, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use runtime::Runtime;
use serde_json::{Value, json};
use std::sync::Arc;

/// The HTTP layer composes managers; domain operations retain their own transactions.
pub struct App {
    pub settings: Arc<Settings>,
    pub database: Arc<Database>,
    pub auth: Auth,
    pub game: Game,
    pub skins: SkinService,
    runtime: Runtime,
}

impl App {
    pub async fn new(settings: Settings) -> Result<Arc<Self>> {
        settings.validate()?;
        let settings = Arc::new(settings);
        let database = Database::open(&settings).await?;
        let auth = Auth::new(settings.clone(), database.clone());
        let game = Game::new(settings.clone(), database.clone(), auth.clone()).await?;
        let skins = SkinService::new(settings.clone(), database.clone(), auth.clone());
        Ok(Arc::new(Self {
            settings,
            database,
            auth,
            game,
            skins,
            runtime: Runtime::new(),
        }))
    }

    pub fn router(self: &Arc<Self>) -> Router {
        Router::new().fallback(dispatch).with_state(self.clone())
    }

    pub fn start_cleanup(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        self.runtime.start_cleanup(self.database.clone())
    }

    async fn respond(&self, request: axum::extract::Request) -> Result<Response> {
        let path = decode_path(request.uri().path()).unwrap_or_default();
        let method = request.method().as_str().to_owned();
        let source = runtime::source_address(&request);
        if self.runtime.rate_limited(&source, &method, &path).await {
            return Err(Error::problem("RATE_LIMITED", "请求过于频繁", 429));
        }
        self.database
            .cleanup_if_due(crate::core::security::now())
            .await?;

        let Some(allowed) = routes::allowed_methods(&path) else {
            let alternate = path.trim_end_matches('/');
            if alternate != path && routes::allowed_methods(alternate).is_some() {
                let host = request
                    .headers()
                    .get(header::HOST)
                    .and_then(|value| value.to_str().ok())
                    .or_else(|| {
                        request
                            .uri()
                            .authority()
                            .map(|authority| authority.as_str())
                    })
                    .unwrap_or("localhost");
                let suffix = request
                    .uri()
                    .query()
                    .map(|query| format!("?{query}"))
                    .unwrap_or_default();
                let scheme = runtime::scheme(&request);
                let location = format!("{scheme}://{host}{alternate}{suffix}");
                return Ok((
                    StatusCode::TEMPORARY_REDIRECT,
                    [(header::LOCATION, location)],
                )
                    .into_response());
            }
            return Ok((StatusCode::NOT_FOUND, Json(json!({"detail":"Not Found"}))).into_response());
        };
        if !allowed
            .split(',')
            .any(|candidate| candidate.trim() == method)
        {
            return Ok((
                StatusCode::METHOD_NOT_ALLOWED,
                [(header::ALLOW, allowed)],
                Json(json!({"detail":"Method Not Allowed"})),
            )
                .into_response());
        }

        let query = request.uri().query().unwrap_or_default();
        let authorization = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let retryable = method == "POST"
            && (path == "/api/v1/sessions/refresh"
                || (path.starts_with("/api/v1/logins/") && path.ends_with("/session")));
        let request_id = if retryable {
            request
                .headers()
                .get("x-request-id")
                .map(|value| value.to_str().map(str::to_owned))
                .transpose()
                .map_err(|_| Error::invalid())?
        } else {
            None
        };
        let fields = Request {
            method,
            path,
            query: url::form_urlencoded::parse(query.as_bytes())
                .into_owned()
                .collect(),
            authorization,
            request_id,
            body: json!({}),
        };

        if fields.path.starts_with("/textures/") {
            return self
                .skins
                .texture(fields.path.trim_start_matches("/textures/"))
                .await;
        }
        if fields.method == "PUT" && fields.path.ends_with("/skin") {
            return self.upload(fields, request).await;
        }
        let fields = read_json(fields, request).await?;
        let reply = if fields.path.starts_with("/api/yggdrasil") {
            self.game.handle(&fields).await?
        } else if fields.method == "DELETE" && fields.path == "/api/v1/me/profile/skin" {
            self.skins.clear(&fields).await?
        } else {
            self.auth.handle(&fields).await?
        };
        Ok(reply.into_response())
    }

    async fn upload(&self, fields: Request, request: axum::extract::Request) -> Result<Response> {
        let native = fields.path.starts_with("/api/yggdrasil/");
        let file_field = if native { "file" } else { "image" };
        let mut form = Multipart::from_request(request, &())
            .await
            .map_err(|_| Error::invalid())?;
        let mut image = None;
        let mut model = if native {
            String::new()
        } else {
            "default".into()
        };
        while let Some(field) = form.next_field().await.map_err(|_| Error::invalid())? {
            let name = field.name().unwrap_or_default().to_owned();
            if name == file_field {
                if field.file_name().is_none() {
                    return Err(Error::invalid());
                }
                let bytes = field.bytes().await.map_err(|_| Error::invalid())?;
                image = Some(bytes.to_vec());
            } else if name == "model" {
                model = field.text().await.map_err(|_| Error::invalid())?;
            }
        }
        let image = image.ok_or_else(Error::invalid)?;
        Ok(self
            .skins
            .upload(&fields, image, &model)
            .await?
            .into_response())
    }
}

async fn dispatch(State(app): State<Arc<App>>, request: axum::extract::Request) -> Response {
    let path = decode_path(request.uri().path()).unwrap_or_default();
    let mut response = match app.respond(request).await {
        Ok(response) => response,
        Err(error) => error_response(&path, error),
    };
    if !path.starts_with("/textures/") {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
    }
    response
}

async fn read_json(mut fields: Request, request: axum::extract::Request) -> Result<Request> {
    if !routes::uses_json(&fields.method, &fields.path) {
        return Ok(fields);
    }
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let mime = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let is_json = content_type.is_empty()
        || mime == "application/json"
        || mime.starts_with("application/") && mime.ends_with("+json");
    let bytes = to_bytes(request.into_body(), 2 * 1024 * 1024)
        .await
        .map_err(|_| Error::problem("INVALID_REQUEST", "请求内容过大", 413))?;
    if bytes.is_empty() && fields.path == "/api/v1/logins" {
        return Ok(fields);
    }
    if !is_json || bytes.is_empty() {
        return Err(Error::invalid());
    }
    fields.body = serde_json::from_slice::<Value>(&bytes).map_err(|_| Error::invalid())?;
    if fields.path == "/api/v1/logins" && fields.body.is_null() {
        fields.body = json!({});
    }
    Ok(fields)
}

fn decode_path(path: &str) -> Option<String> {
    let mut decoded = Vec::new();
    for segment in path.split('/') {
        let value = percent_encoding::percent_decode_str(segment)
            .decode_utf8()
            .ok()?;
        if value.contains('/') {
            return None;
        }
        decoded.push(value.into_owned());
    }
    Some(decoded.join("/"))
}

fn error_response(path: &str, error: Error) -> Response {
    if !path.starts_with("/api/yggdrasil")
        || matches!(
            error.code.as_str(),
            "DATABASE_UNAVAILABLE" | "RATE_LIMITED" | "SERVICE_UNAVAILABLE"
        )
    {
        return error.into_response();
    }
    let validation = error.code == "INVALID_REQUEST";
    let status = if validation {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    };
    let name = if validation {
        "IllegalArgumentException"
    } else {
        "ForbiddenOperationException"
    };
    let message = if validation {
        "Invalid request.".to_owned()
    } else {
        error.message
    };
    (status, Json(json!({"error":name,"errorMessage":message}))).into_response()
}
