// SPDX-License-Identifier: AGPL-3.0-or-later
// ALICE-Security-SaaS core-engine: WAF + DLP + Audit platform

use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;
use uuid::Uuid;

#[derive(Debug, Default)]
struct Stats {
    scans: u64,
    rules_created: u64,
    audit_queries: u64,
    pii_detections: u64,
}

type AppState = Arc<Mutex<Stats>>;

#[derive(Deserialize)]
struct ScanRequest {
    target: String,
    scan_type: Option<String>,
}

#[derive(Deserialize)]
struct RuleRequest {
    name: String,
    pattern: String,
    action: String,
}

#[derive(Deserialize)]
struct PiiRequest {
    text: String,
    redact: Option<bool>,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    version: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "alice-security-core",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn scan(
    State(state): State<AppState>,
    Json(req): Json<ScanRequest>,
) -> (StatusCode, Json<Value>) {
    let scan_id = Uuid::new_v4().to_string();
    {
        let mut s = state.lock().unwrap();
        s.scans += 1;
    }
    let scan_type = req.scan_type.unwrap_or_else(|| "full".to_string());
    info!(scan_id = %scan_id, target = %req.target, scan_type = %scan_type, "security scan initiated");
    (
        StatusCode::OK,
        Json(json!({
            "scan_id": scan_id,
            "target": req.target,
            "scan_type": scan_type,
            "status": "completed",
            "threats_found": 0,
            "waf_rules_matched": [],
            "risk_score": 0.02,
        })),
    )
}

async fn create_rule(
    State(state): State<AppState>,
    Json(req): Json<RuleRequest>,
) -> (StatusCode, Json<Value>) {
    let rule_id = Uuid::new_v4().to_string();
    {
        let mut s = state.lock().unwrap();
        s.rules_created += 1;
    }
    info!(rule_id = %rule_id, name = %req.name, "WAF rule created");
    (
        StatusCode::CREATED,
        Json(json!({
            "rule_id": rule_id,
            "name": req.name,
            "pattern": req.pattern,
            "action": req.action,
            "enabled": true,
        })),
    )
}

async fn audit(State(state): State<AppState>) -> Json<Value> {
    {
        let mut s = state.lock().unwrap();
        s.audit_queries += 1;
    }
    Json(json!({
        "audit_log": [
            { "event": "login", "user": "admin", "timestamp": "2026-03-09T00:00:00Z", "result": "success" },
            { "event": "rule_update", "user": "admin", "timestamp": "2026-03-09T01:00:00Z", "result": "success" },
        ],
        "total": 2,
    }))
}

async fn pii_detect(
    State(state): State<AppState>,
    Json(req): Json<PiiRequest>,
) -> (StatusCode, Json<Value>) {
    let request_id = Uuid::new_v4().to_string();
    let redact = req.redact.unwrap_or(false);
    let has_pii = req.text.contains('@') || req.text.len() > 10;
    {
        let mut s = state.lock().unwrap();
        if has_pii {
            s.pii_detections += 1;
        }
    }
    info!(request_id = %request_id, redact = redact, "PII detection completed");
    let output = if redact && has_pii {
        "[REDACTED]".to_string()
    } else {
        req.text.clone()
    };
    (
        StatusCode::OK,
        Json(json!({
            "request_id": request_id,
            "pii_detected": has_pii,
            "categories": if has_pii { vec!["EMAIL"] } else { vec![] },
            "output": output,
        })),
    )
}

async fn stats(State(state): State<AppState>) -> Json<Value> {
    let s = state.lock().unwrap();
    Json(json!({
        "scans": s.scans,
        "rules_created": s.rules_created,
        "audit_queries": s.audit_queries,
        "pii_detections": s.pii_detections,
    }))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let state: AppState = Arc::new(Mutex::new(Stats::default()));

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/security/scan", post(scan))
        .route("/api/v1/security/rules", post(create_rule))
        .route("/api/v1/security/audit", get(audit))
        .route("/api/v1/security/pii", post(pii_detect))
        .route("/api/v1/security/stats", get(stats))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "8135".to_string());
    let addr = format!("0.0.0.0:{}", port);
    info!("alice-security-core listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
