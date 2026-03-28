// SPDX-License-Identifier: AGPL-3.0-or-later
// ALICE-Security-SaaS api-gateway

use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use dashmap::DashMap;
use serde_json::{json, Value};
use std::sync::Arc;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;

struct GatewayState {
    upstream: String,
    client: reqwest::Client,
    request_counts: DashMap<String, u64>,
}

type AppState = Arc<GatewayState>;

async fn health(State(state): State<AppState>) -> Json<Value> {
    let total: u64 = state.request_counts.iter().map(|e| *e.value()).sum();
    Json(json!({
        "status": "ok",
        "service": "alice-security-gateway",
        "upstream": state.upstream,
        "total_requests": total,
    }))
}

async fn proxy_handler(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    *state
        .request_counts
        .entry("proxied".to_string())
        .or_insert(0) += 1;
    match state
        .client
        .get(format!("{}/health", state.upstream))
        .send()
        .await
    {
        Ok(resp) => {
            let body: Value = resp.json().await.unwrap_or(json!({}));
            (StatusCode::OK, Json(body))
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": e.to_string() })),
        ),
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let upstream = std::env::var("UPSTREAM_URL")
        .unwrap_or_else(|_| "http://localhost:8135".to_string());

    let state: AppState = Arc::new(GatewayState {
        upstream,
        client: reqwest::Client::new(),
        request_counts: DashMap::new(),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/upstream/health", get(proxy_handler))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let port = std::env::var("GATEWAY_PORT").unwrap_or_else(|_| "9135".to_string());
    let addr = format!("0.0.0.0:{}", port);
    info!("alice-security-gateway listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
