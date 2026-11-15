use crate::{
    core::security::now,
    storage::{Database, maintenance::cleanup_textures},
};
use axum::extract::ConnectInfo;
use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

pub struct Runtime {
    requests: Mutex<HashMap<(String, bool), VecDeque<Instant>>>,
}

impl Runtime {
    pub fn new() -> Self {
        Self {
            requests: Mutex::new(HashMap::new()),
        }
    }

    pub async fn rate_limited(&self, source: &str, method: &str, path: &str) -> bool {
        let sensitive = method == "POST"
            && (path.starts_with("/api/v1/")
                || path.ends_with("/authenticate")
                || path.ends_with("/signout"));
        let limit = if sensitive { 20 } else { 300 };
        let timestamp = Instant::now();
        let mut requests = self.requests.lock().await;
        if requests.len() > 10000 {
            requests.retain(|_, values| {
                values
                    .back()
                    .is_some_and(|value| timestamp.duration_since(*value) < Duration::from_secs(60))
            });
        }
        let bucket = requests.entry((source.to_owned(), sensitive)).or_default();
        while bucket
            .front()
            .is_some_and(|value| timestamp.duration_since(*value) >= Duration::from_secs(60))
        {
            bucket.pop_front();
        }
        if bucket.len() >= limit {
            return true;
        }
        bucket.push_back(timestamp);
        false
    }

    pub fn start_cleanup(&self, database: Arc<Database>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut next_textures = 0;
            loop {
                let timestamp = now();
                if database.cleanup_if_due(timestamp).await.is_err() {
                    tracing::warn!("Database cleanup failed");
                }
                if timestamp >= next_textures {
                    if cleanup_textures(&database, timestamp, 86400).await.is_err() {
                        tracing::warn!("Texture cleanup failed");
                    }
                    next_textures = timestamp + 3600;
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        })
    }
}

pub fn source_address(request: &axum::extract::Request) -> String {
    let Some(ConnectInfo(peer)) = request
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
    else {
        return "unknown".into();
    };
    // A local reverse proxy must replace X-Forwarded-For with the client address.
    if peer.ip().is_loopback()
        && let Some(address) = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<IpAddr>().ok())
    {
        return address.to_string();
    }
    peer.ip().to_string()
}

pub fn scheme(request: &axum::extract::Request) -> &str {
    let trusted = request
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .is_some_and(|ConnectInfo(peer)| peer.ip().is_loopback());
    if trusted
        && let Some(value @ ("http" | "https")) = request
            .headers()
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
    {
        return value;
    }
    request.uri().scheme_str().unwrap_or("http")
}
