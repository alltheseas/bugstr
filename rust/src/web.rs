//! Web server for the Bugstr crash report dashboard.
//!
//! Provides a REST API and serves an embedded static dashboard.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rust_embed::Embed;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

use crate::storage::{CrashGroup, CrashReport, CrashStorage};
use crate::symbolication::{Platform, Symbolicator, SymbolicationContext};

/// Embedded static files for the dashboard.
#[derive(Embed)]
#[folder = "static/"]
struct Assets;

/// Shared application state.
pub struct AppState {
    pub storage: Mutex<CrashStorage>,
    pub symbolicator: Option<Arc<Symbolicator>>,
}

/// Creates the web server router.
pub fn create_router(state: Arc<AppState>) -> Router {
    // CORS: Only allow same-origin requests by default.
    // The dashboard is served from the same origin, so cross-origin
    // requests are not needed. This is more secure than allowing Any.
    let cors = CorsLayer::new();

    Router::new()
        // API routes
        .route("/api/crashes", get(get_crashes))
        .route("/api/crashes/{id}", get(get_crash))
        .route("/api/groups", get(get_groups))
        .route("/api/stats", get(get_stats))
        .route("/api/symbolicate", post(symbolicate_stack))
        // Static files and SPA fallback
        .route("/", get(index_handler))
        .route("/{*path}", get(static_handler))
        .layer(cors)
        .with_state(state)
}

/// GET /api/crashes - List recent crash reports
async fn get_crashes(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let storage = state.storage.lock().await;
    match storage.get_recent(100) {
        Ok(crashes) => Json(crashes.into_iter().map(CrashJson::from).collect::<Vec<_>>()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// GET /api/crashes/:id - Get a single crash report
async fn get_crash(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let storage = state.storage.lock().await;
    match storage.get_by_id(id) {
        Ok(Some(crash)) => Json(CrashJson::from(crash)).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// GET /api/groups - Get crash groups by exception type
async fn get_groups(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let storage = state.storage.lock().await;
    match storage.get_groups(50) {
        Ok(groups) => Json(groups.into_iter().map(GroupJson::from).collect::<Vec<_>>()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// GET /api/stats - Get dashboard statistics
async fn get_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let storage = state.storage.lock().await;
    match storage.count() {
        Ok(total) => Json(StatsJson { total_crashes: total }).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// POST /api/symbolicate - Symbolicate a stack trace
async fn symbolicate_stack(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SymbolicateRequest>,
) -> impl IntoResponse {
    let Some(ref symbolicator) = state.symbolicator else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "Symbolication not configured. Start server with --mappings option."
            }))
        ).into_response();
    };

    let platform = Platform::from_str(&request.platform);
    let context = SymbolicationContext {
        platform,
        app_id: request.app_id,
        version: request.version,
        build_id: request.build_id,
    };

    // Clone Arc for move into spawn_blocking
    let symbolicator = Arc::clone(symbolicator);
    let stack_trace = request.stack_trace;

    // Run symbolication in blocking task pool to avoid blocking async runtime
    let result = tokio::task::spawn_blocking(move || {
        symbolicator.symbolicate(&stack_trace, &context)
    }).await;

    match result {
        Ok(Ok(result)) => Json(SymbolicateResponse {
            symbolicated_count: result.symbolicated_count,
            total_count: result.total_count,
            percentage: result.percentage(),
            display: result.display(),
            frames: result.frames.iter().map(|f| FrameJson {
                raw: f.raw.clone(),
                function: f.function.clone(),
                file: f.file.clone(),
                line: f.line,
                column: f.column,
                symbolicated: f.symbolicated,
            }).collect(),
        }).into_response(),
        Ok(Err(e)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() }))
        ).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("Task failed: {}", e) }))
        ).into_response(),
    }
}

/// Serve index.html
async fn index_handler() -> impl IntoResponse {
    match Assets::get("index.html") {
        Some(content) => Html(content.data.to_vec()).into_response(),
        None => (StatusCode::NOT_FOUND, "index.html not found").into_response(),
    }
}

/// Serve static files or fallback to index.html for SPA routing
async fn static_handler(Path(path): Path<String>) -> impl IntoResponse {
    let path = path.trim_start_matches('/');

    // Try to serve the exact file
    if let Some(content) = Assets::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        return Response::builder()
            .header("Content-Type", mime.as_ref())
            .body(content.data.to_vec().into())
            .unwrap();
    }

    // Fallback to index.html for client-side routing
    match Assets::get("index.html") {
        Some(content) => Html(content.data.to_vec()).into_response(),
        None => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

// JSON response types with serde

#[derive(serde::Serialize)]
struct CrashJson {
    id: i64,
    event_id: String,
    sender_pubkey: String,
    received_at: i64,
    created_at: i64,
    app_name: Option<String>,
    app_version: Option<String>,
    exception_type: Option<String>,
    message: Option<String>,
    stack_trace: Option<String>,
    raw_content: String,
    environment: Option<String>,
    release: Option<String>,
}

impl From<CrashReport> for CrashJson {
    fn from(r: CrashReport) -> Self {
        Self {
            id: r.id,
            event_id: r.event_id,
            sender_pubkey: r.sender_pubkey,
            received_at: r.received_at,
            created_at: r.created_at,
            app_name: r.app_name,
            app_version: r.app_version,
            exception_type: r.exception_type,
            message: r.message,
            stack_trace: r.stack_trace,
            raw_content: r.raw_content,
            environment: r.environment,
            release: r.release,
        }
    }
}

#[derive(serde::Serialize)]
struct GroupJson {
    exception_type: String,
    count: i64,
    first_seen: i64,
    last_seen: i64,
    app_versions: Vec<String>,
}

impl From<CrashGroup> for GroupJson {
    fn from(g: CrashGroup) -> Self {
        Self {
            exception_type: g.exception_type,
            count: g.count,
            first_seen: g.first_seen,
            last_seen: g.last_seen,
            app_versions: g.app_versions,
        }
    }
}

#[derive(serde::Serialize)]
struct StatsJson {
    total_crashes: i64,
}

// Symbolication request/response types

#[derive(serde::Deserialize)]
struct SymbolicateRequest {
    /// Stack trace to symbolicate
    stack_trace: String,
    /// Platform: android, electron, flutter, rust, go, python, react-native
    platform: String,
    /// Optional application ID
    app_id: Option<String>,
    /// Optional version
    version: Option<String>,
    /// Optional build ID
    build_id: Option<String>,
}

#[derive(serde::Serialize)]
struct SymbolicateResponse {
    symbolicated_count: usize,
    total_count: usize,
    percentage: f64,
    display: String,
    frames: Vec<FrameJson>,
}

#[derive(serde::Serialize)]
struct FrameJson {
    raw: String,
    function: Option<String>,
    file: Option<String>,
    line: Option<u32>,
    column: Option<u32>,
    symbolicated: bool,
}
