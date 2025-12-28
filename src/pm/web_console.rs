use crate::pm::config::WebConsoleConfig;
use crate::pm::daemon::{dispatch_async, DaemonState};
use crate::pm::cgroup;
use crate::pm::rpc::Request;
use askama::Template;
use axum::extract::State;
use axum::extract::Path as AxumPath;
use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response as AxumResponse};
use axum::routing::{get, post};
use axum::{middleware, Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rand::RngCore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use time::{Duration as TimeDuration, OffsetDateTime};

#[derive(Clone)]
struct WebState {
    daemon: Arc<Mutex<DaemonState>>,
    users: Arc<HashMap<String, String>>, // username -> bcrypt hash
    auth_cache: Arc<Mutex<AuthCache>>,
    tls_enabled: bool,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct AuthCacheKey {
    user: String,
    expected_hash: String,
    pass: String,
}

struct AuthCache {
    // Cache bcrypt verification result. Key includes the current stored hash, so when the password
    // changes (hash changes), cached results stop matching automatically.
    //
    // NOTE: This key includes the plaintext password (bounded cache). User explicitly accepted this tradeoff.
    entries: HashMap<AuthCacheKey, bool>,
    order: VecDeque<AuthCacheKey>,
}

impl AuthCache {
    const MAX_ENTRIES: usize = 1024;

    fn new() -> Self {
        Self { entries: HashMap::new(), order: VecDeque::new() }
    }

    fn get(&mut self, key: &AuthCacheKey) -> Option<bool> {
        self.entries.get(key).copied()
    }

    fn put(&mut self, key: AuthCacheKey, val: bool) {
        if !self.entries.contains_key(&key) {
            self.order.push_back(key.clone());
        }
        self.entries.insert(key, val);
        while self.entries.len() > Self::MAX_ENTRIES {
            if let Some(k) = self.order.pop_front() {
                self.entries.remove(&k);
            } else {
                break;
            }
        }
    }
}

pub(super) fn start_web_console(state: Arc<Mutex<DaemonState>>) {
    let (cfg, shutting_down): (WebConsoleConfig, Arc<AtomicBool>) = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        (st.cfg.web_console.clone(), Arc::clone(&st.shutting_down))
    };

    if !cfg.enabled {
        return;
    }

    let users = match parse_htpasswd_users(&cfg) {
        Ok(u) => u,
        Err(e) => {
            crate::pm::daemon::pm_event(
                "web",
                None,
                format!("web_console disabled: invalid auth config: {e}"),
            );
            return;
        }
    };

    let bind_addr: SocketAddr = match format!("{}:{}", cfg.bind, cfg.port).parse() {
        Ok(a) => a,
        Err(e) => {
            crate::pm::daemon::pm_event(
                "web",
                None,
                format!("web_console disabled: invalid bind/port: {e}"),
            );
            return;
        }
    };

    let st = WebState {
        daemon: Arc::clone(&state),
        users: Arc::new(users),
        auth_cache: Arc::new(Mutex::new(AuthCache::new())),
        tls_enabled: cfg.tls.enabled,
    };

    crate::pm::daemon::tasks().spawn(async move {
        let app = build_router(st);
        if let Err(e) = serve(cfg, bind_addr, app, shutting_down).await {
            crate::pm::daemon::pm_event("web", None, format!("web_console stopped: {e}"));
        }
    });
}

fn parse_htpasswd_users(cfg: &WebConsoleConfig) -> anyhow::Result<HashMap<String, String>> {
    let mut out = HashMap::new();
    for entry in &cfg.auth.basic.users {
        let t = entry.trim();
        if t.is_empty() {
            continue;
        }
        let (user, hash) = t
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("invalid htpasswd entry (missing ':'): {t:?}"))?;
        let user = user.trim();
        let hash = hash.trim();
        anyhow::ensure!(!user.is_empty(), "invalid htpasswd entry (empty username): {t:?}");
        anyhow::ensure!(!hash.is_empty(), "invalid htpasswd entry (empty hash): {t:?}");
        // htpasswd -B often emits $2y$...; normalize once so we don't allocate per request.
        let normalized = hash.replace("$2y$", "$2b$");
        out.insert(user.to_string(), normalized);
    }
    anyhow::ensure!(
        !out.is_empty(),
        "no basic auth users configured (web_console.auth.basic.users is empty)"
    );
    Ok(out)
}

fn build_router(state: WebState) -> Router {
    let auth_state = state.clone();
    let csrf_state = state.clone();
    let inner = Router::new()
        .route("/", get(|| async { Redirect::temporary("status") }))
        .route("/status", get(status_page))
        .route("/favicon.ico", get(favicon_ico))
        // Common typo/alias
        .route("/favico.ico", get(favicon_ico))
        .route("/static/logo.png", get(static_logo_png))
        .route("/icons/:name", get(icon_asset))
        .route("/rpc", post(jsonrpc))
        .with_state(state)
        .layer(middleware::from_fn_with_state(auth_state, basic_auth_middleware))
        .layer(middleware::from_fn_with_state(csrf_state, csrf_middleware));

    // Mount the entire web console under a stable context path for reverse proxies.
    Router::new()
        .route("/", get(|| async { Redirect::temporary("/processmaster/status") }))
        .route("/index.html", get(|| async { Redirect::temporary("/processmaster/status") }))
        .route("/index.htm", get(|| async { Redirect::temporary("/processmaster/status") }))
        // Also serve icons at the root path, so browsers that request `/favicon.ico` work.
        .route("/favicon.ico", get(favicon_ico))
        .route("/favico.ico", get(favicon_ico))
        .route("/icons/:name", get(icon_asset))
        // Compatibility alias (common misspelling): /procressmaster/static/logo.png
        .route("/procressmaster/static/logo.png", get(static_logo_png))
        .nest("/processmaster", inner)
}

// ---------------- Embedded static assets (icons) ----------------

const ICON_FAVICON_ICO: &[u8] = include_bytes!("../../templates/icons/favicon.ico");
const ICON_ANDROID_192: &[u8] = include_bytes!("../../templates/icons/android-chrome-192x192.png");
const ICON_ANDROID_512: &[u8] = include_bytes!("../../templates/icons/android-chrome-512x512.png");
const ICON_FAVICON_16: &[u8] = include_bytes!("../../templates/icons/favicon-16x16.png");
const ICON_FAVICON_32: &[u8] = include_bytes!("../../templates/icons/favicon-32x32.png");
const ICON_APPLE_TOUCH: &[u8] = include_bytes!("../../templates/icons/apple-touch-icon.png");

fn bytes_response(content_type: &'static str, bytes: &'static [u8]) -> AxumResponse {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        Body::from(bytes),
    )
        .into_response()
}

async fn favicon_ico() -> AxumResponse {
    bytes_response("image/x-icon", ICON_FAVICON_ICO)
}

async fn static_logo_png() -> AxumResponse {
    // Serve the logo from embedded bytes; currently reusing the 192x192 icon.
    bytes_response("image/png", ICON_ANDROID_192)
}

async fn icon_asset(AxumPath(name): AxumPath<String>) -> AxumResponse {
    match name.as_str() {
        "android-chrome-192x192.png" => bytes_response("image/png", ICON_ANDROID_192),
        "android-chrome-512x512.png" => bytes_response("image/png", ICON_ANDROID_512),
        "favicon-16x16.png" => bytes_response("image/png", ICON_FAVICON_16),
        "favicon-32x32.png" => bytes_response("image/png", ICON_FAVICON_32),
        "apple-touch-icon.png" => bytes_response("image/png", ICON_APPLE_TOUCH),
        // Also allow `/icons/favicon.ico` for completeness
        "favicon.ico" => bytes_response("image/x-icon", ICON_FAVICON_ICO),
        _ => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

async fn basic_auth_middleware(
    State(st): State<WebState>,
    req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> impl IntoResponse {
    let headers = req.headers();
    match check_basic_auth(&st.users, &st.auth_cache, headers) {
        Ok(()) => next.run(req).await,
        Err(msg) => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, r#"Basic realm="processmaster""#)],
            msg,
        )
            .into_response(),
    }
}

fn check_basic_auth(
    users: &HashMap<String, String>,
    auth_cache: &Arc<Mutex<AuthCache>>,
    headers: &axum::http::HeaderMap,
) -> Result<(), String> {
    let Some(v) = headers.get(header::AUTHORIZATION) else {
        return Err("missing Authorization header".to_string());
    };
    let Ok(s) = v.to_str() else {
        return Err("invalid Authorization header".to_string());
    };
    let s = s.trim();
    let Some(b64) = s.strip_prefix("Basic ").or_else(|| s.strip_prefix("basic ")) else {
        return Err("expected Basic authorization".to_string());
    };
    let decoded = BASE64
        .decode(b64.trim().as_bytes())
        .map_err(|_| "invalid base64 in Authorization".to_string())?;
    let decoded = String::from_utf8(decoded).map_err(|_| "invalid utf8 in Authorization".to_string())?;
    let (user, pass) = decoded
        .split_once(':')
        .ok_or_else(|| "invalid basic auth payload".to_string())?;
    let Some(expected_hash) = users.get(user) else {
        return Err("invalid credentials".to_string());
    };

    let key = AuthCacheKey {
        user: user.to_string(),
        expected_hash: expected_hash.clone(),
        pass: pass.to_string(),
    };
    // Cache lookup/insert around bcrypt to avoid repeated work. Cache is bounded; no TTL.
    if let Ok(mut c) = auth_cache.lock() {
        if let Some(cached) = c.get(&key) {
            return if cached { Ok(()) } else { Err("invalid credentials".to_string()) };
        }
        let ok = bcrypt::verify(pass, expected_hash).map_err(|_| "invalid credentials".to_string())?;
        c.put(key, ok);
        return ok.then_some(()).ok_or_else(|| "invalid credentials".to_string());
    }

    // If cache lock is poisoned/unavailable, fall back to a direct verify.
    bcrypt::verify(pass, expected_hash)
        .map_err(|_| "invalid credentials".to_string())?
        .then_some(())
        .ok_or_else(|| "invalid credentials".to_string())
}

// ---------------- CSRF ----------------

const CSRF_COOKIE: &str = "pm_csrf";
const CSRF_HEADER: &str = "x-csrf-token";

async fn csrf_middleware(
    State(st): State<WebState>,
    req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> impl IntoResponse {
    // Set CSRF cookie on GETs if missing (used by the UI).
    // Enforce CSRF on POST /rpc: require X-CSRF-Token == cookie value.
    let method = req.method().clone();
    let uri = req.uri().path().to_string();
    let headers = req.headers().clone();

    let cookie_token = cookie_get(&headers, CSRF_COOKIE);
    if method == axum::http::Method::POST && uri == "/processmaster/rpc" {
        let hdr = headers
            .get(CSRF_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string());
        if cookie_token.is_none() || hdr.is_none() || cookie_token.as_deref() != hdr.as_deref() {
            return (StatusCode::FORBIDDEN, "csrf check failed").into_response();
        }
    }

    let mut resp = next.run(req).await;

    if method == axum::http::Method::GET {
        if cookie_token.is_none() {
            let t = new_csrf_token();
            let mut cookie = format!("{CSRF_COOKIE}={t}; Path=/processmaster/; SameSite=Strict");
            if st.tls_enabled {
                cookie.push_str("; Secure");
            }
            cookie.push_str("; HttpOnly");
            resp.headers_mut()
                .append(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
        }
    }

    resp
}

fn new_csrf_token() -> String {
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

fn cookie_get(headers: &HeaderMap, name: &str) -> Option<String> {
    let v = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in v.split(';') {
        let t = part.trim();
        if let Some((k, val)) = t.split_once('=') {
            if k.trim() == name {
                return Some(val.trim().to_string());
            }
        }
    }
    None
}

// ---------------- Askama pages ----------------

#[derive(Template)]
#[template(path = "status.html")]
struct StatusTemplate<'a> {
    title: &'a str,
    csrf_token: &'a str,
    admin_actions: Vec<AdminActionButton>,
    build_banner: String,
}

#[derive(Clone)]
struct AdminActionButton {
    name: String,
    label: String,
}

async fn status_page(State(_st): State<WebState>, headers: HeaderMap) -> AxumResponse {
    let token = cookie_get(&headers, CSRF_COOKIE).unwrap_or_else(|| "".to_string());
    // Build banner is computed from build-time env vars (see build.rs).
    let admin_actions = {
        let st = _st.daemon.lock().unwrap_or_else(|p| p.into_inner());
        st.cfg
            .admin_actions
            .iter()
            .map(|(name, a)| AdminActionButton {
                name: name.clone(),
                label: a
                    .label
                    .clone()
                    .unwrap_or_else(|| name.clone()),
            })
            .collect::<Vec<_>>()
    };
    let t = StatusTemplate {
        title: "processmaster",
        csrf_token: &token,
        admin_actions,
        build_banner: crate::pm::build_info::banner(),
    };
    match t.render() {
        Ok(s) => Html(s).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ---------------- JSON-RPC 2.0 ----------------

#[derive(Debug, serde::Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
    id: serde_json::Value,
}

#[derive(Debug, serde::Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

#[derive(Debug, serde::Serialize)]
struct JsonRpcResponse<T: serde::Serialize> {
    jsonrpc: &'static str,
    id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

async fn jsonrpc(State(st): State<WebState>, Json(req): Json<JsonRpcRequest>) -> impl IntoResponse {
    if req.jsonrpc != "2.0" {
        return (
            StatusCode::BAD_REQUEST,
            Json(JsonRpcResponse::<serde_json::Value> {
                jsonrpc: "2.0",
                id: req.id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32600,
                    message: "invalid jsonrpc version".to_string(),
                }),
            }),
        );
    }

    // Web-console specific methods (not routed through daemon::dispatch_async), used for UX features.
    // These return lightweight objects (ok/message/...) and can directly inspect daemon config/state.
    match req.method.as_str() {
        "service_details" => {
            let app = req
                .params
                .get("app")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if app.is_empty() {
                let v = serde_json::json!({ "ok": false, "message": "missing/empty param: app" });
                return (
                    StatusCode::OK,
                    Json(JsonRpcResponse::<serde_json::Value> {
                        jsonrpc: "2.0",
                        id: req.id,
                        result: Some(v),
                        error: None,
                    }),
                );
            }

            let cfg = {
                let st = st.daemon.lock().unwrap_or_else(|p| p.into_inner());
                st.cfg.clone()
            };

            let cg_dir = match service_cgroup_dir(&cfg, &app) {
                Ok(p) => p,
                Err(e) => {
                    let v = serde_json::json!({ "ok": false, "message": e.to_string() });
                    return (
                        StatusCode::OK,
                        Json(JsonRpcResponse::<serde_json::Value> {
                            jsonrpc: "2.0",
                            id: req.id,
                            result: Some(v),
                            error: None,
                        }),
                    );
                }
            };

            if let Err(e) = std::fs::metadata(&cg_dir) {
                let v = serde_json::json!({
                    "ok": false,
                    "message": format!("cgroup dir not found: {}: {e}", cg_dir.display()),
                    "app": app,
                    "cgroup_dir": cg_dir.display().to_string(),
                });
                return (
                    StatusCode::OK,
                    Json(JsonRpcResponse::<serde_json::Value> {
                        jsonrpc: "2.0",
                        id: req.id,
                        result: Some(v),
                        error: None,
                    }),
                );
            }

            let snap = match cgroup::read_resource_snapshot(&cg_dir) {
                Ok(s) => s,
                Err(e) => {
                    let v = serde_json::json!({
                        "ok": false,
                        "message": e.to_string(),
                        "app": app,
                        "cgroup_dir": cg_dir.display().to_string(),
                    });
                    return (
                        StatusCode::OK,
                        Json(JsonRpcResponse::<serde_json::Value> {
                            jsonrpc: "2.0",
                            id: req.id,
                            result: Some(v),
                            error: None,
                        }),
                    );
                }
            };

            let v = serde_json::json!({
                "ok": true,
                "message": "",
                "app": app,
                "snapshot": snap,
            });
            return (
                StatusCode::OK,
                Json(JsonRpcResponse::<serde_json::Value> {
                    jsonrpc: "2.0",
                    id: req.id,
                    result: Some(v),
                    error: None,
                }),
            );
        }
        "admin_actions_pids" => {
            let cfg = {
                let st = st.daemon.lock().unwrap_or_else(|p| p.into_inner());
                st.cfg.clone()
            };
            let admin_cg = match admin_actions_cgroup_dir(&cfg) {
                Ok(p) => p,
                Err(e) => {
                    let v = serde_json::json!({ "ok": false, "message": e.to_string(), "pids": [] });
                    return (
                        StatusCode::OK,
                        Json(JsonRpcResponse::<serde_json::Value> {
                            jsonrpc: "2.0",
                            id: req.id,
                            result: Some(v),
                            error: None,
                        }),
                    );
                }
            };
            let pids = match cgroup::list_pids(&admin_cg) {
                Ok(v) => v,
                Err(e) => {
                    let v = serde_json::json!({ "ok": false, "message": e.to_string(), "pids": [] });
                    return (
                        StatusCode::OK,
                        Json(JsonRpcResponse::<serde_json::Value> {
                            jsonrpc: "2.0",
                            id: req.id,
                            result: Some(v),
                            error: None,
                        }),
                    );
                }
            };
            let v = serde_json::json!({ "ok": true, "message": "", "pids": pids });
            return (
                StatusCode::OK,
                Json(JsonRpcResponse::<serde_json::Value> {
                    jsonrpc: "2.0",
                    id: req.id,
                    result: Some(v),
                    error: None,
                }),
            );
        }
        "admin_actions_kill" => {
            let cfg = {
                let st = st.daemon.lock().unwrap_or_else(|p| p.into_inner());
                st.cfg.clone()
            };
            let admin_cg = match admin_actions_cgroup_dir(&cfg) {
                Ok(p) => p,
                Err(e) => {
                    let v = serde_json::json!({ "ok": false, "message": e.to_string() });
                    return (
                        StatusCode::OK,
                        Json(JsonRpcResponse::<serde_json::Value> {
                            jsonrpc: "2.0",
                            id: req.id,
                            result: Some(v),
                            error: None,
                        }),
                    );
                }
            };
            let before = cgroup::list_pids(&admin_cg).unwrap_or_default();
            if let Err(e) = cgroup::kill_all_pids(&admin_cg) {
                let v = serde_json::json!({ "ok": false, "message": e.to_string() });
                return (
                    StatusCode::OK,
                    Json(JsonRpcResponse::<serde_json::Value> {
                        jsonrpc: "2.0",
                        id: req.id,
                        result: Some(v),
                        error: None,
                    }),
                );
            }
            let v = serde_json::json!({
                "ok": true,
                "message": format!("sent cgroup.kill to {} (pids_before={})", admin_cg.display(), before.len()),
            });
            return (
                StatusCode::OK,
                Json(JsonRpcResponse::<serde_json::Value> {
                    jsonrpc: "2.0",
                    id: req.id,
                    result: Some(v),
                    error: None,
                }),
            );
        }
        _ => {}
    }

    let r = match map_method_to_request(&req.method, &req.params) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(JsonRpcResponse::<serde_json::Value> {
                    jsonrpc: "2.0",
                    id: req.id,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32602,
                        message: e,
                    }),
                }),
            );
        }
    };

    match dispatch_async(Arc::clone(&st.daemon), r).await {
        Ok(resp) => {
            let v = serde_json::to_value(resp).unwrap_or_else(|e| {
                serde_json::Value::String(format!("failed to serialize response: {e}"))
            });
            (
                StatusCode::OK,
                Json(JsonRpcResponse::<serde_json::Value> {
                    jsonrpc: "2.0",
                    id: req.id,
                    result: Some(v),
                    error: None,
                }),
            )
        }
        Err(e) => (
            StatusCode::OK,
            Json(JsonRpcResponse::<serde_json::Value> {
                jsonrpc: "2.0",
                id: req.id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32000,
                    message: e.to_string(),
                }),
            }),
        ),
    }
}

fn admin_actions_cgroup_dir(cfg: &crate::pm::config::MasterConfig) -> anyhow::Result<PathBuf> {
    let name = cfg.cgroup_name.trim();
    anyhow::ensure!(!name.is_empty(), "cgroup.name is empty");
    anyhow::ensure!(
        !name.split('/').any(|seg| seg == ".."),
        "cgroup.name must not contain '..'"
    );
    let master = PathBuf::from(&cfg.cgroup_root).join(name.trim_start_matches('/'));
    Ok(master.join("admin_actions"))
}

fn service_cgroup_dir(cfg: &crate::pm::config::MasterConfig, app: &str) -> anyhow::Result<PathBuf> {
    let name = cfg.cgroup_name.trim();
    anyhow::ensure!(!name.is_empty(), "cgroup.name is empty");
    anyhow::ensure!(
        !name.split('/').any(|seg| seg == ".."),
        "cgroup.name must not contain '..'"
    );
    let app = app.trim();
    anyhow::ensure!(!app.is_empty(), "app name is empty");
    anyhow::ensure!(
        !app.split('/').any(|seg| seg == ".." || seg.is_empty()),
        "app name must not contain '/' or '..'"
    );
    let master = PathBuf::from(&cfg.cgroup_root).join(name.trim_start_matches('/'));
    Ok(master.join(format!("pm-{app}")))
}

fn map_method_to_request(method: &str, params: &serde_json::Value) -> Result<Request, String> {
    let obj = params.as_object().cloned().unwrap_or_default();
    let get_s = |k: &str| obj.get(k).and_then(|v| v.as_str()).map(|s| s.to_string());
    let get_b = |k: &str| obj.get(k).and_then(|v| v.as_bool());
    let get_u = |k: &str| obj.get(k).and_then(|v| v.as_u64()).map(|x| x as usize);

    match method {
        "status" => Ok(Request::Status { name: get_s("name") }),
        "events" => Ok(Request::Events {
            name: get_s("name"),
            n: get_u("n").unwrap_or(200),
        }),
        "logs" => {
            let name = get_s("name").ok_or_else(|| "missing param: name".to_string())?;
            Ok(Request::Logs {
                name,
                n: get_u("n").unwrap_or(50),
            })
        }
        "update" => Ok(Request::Update),
        "admin_action" => {
            let name = get_s("name").ok_or_else(|| "missing param: name".to_string())?;
            Ok(Request::AdminAction { name })
        }
        "start_all" => Ok(Request::StartAll {
            force: get_b("force").unwrap_or(false),
        }),
        "stop_all" => Ok(Request::StopAll),
        "restart_all" => Ok(Request::RestartAll {
            force: get_b("force").unwrap_or(false),
        }),
        "start" => {
            let name = get_s("name").ok_or_else(|| "missing param: name".to_string())?;
            Ok(Request::Start {
                name,
                force: get_b("force").unwrap_or(false),
            })
        }
        "stop" => {
            let name = get_s("name").ok_or_else(|| "missing param: name".to_string())?;
            Ok(Request::Stop { name })
        }
        "restart" => {
            let name = get_s("name").ok_or_else(|| "missing param: name".to_string())?;
            Ok(Request::Restart {
                name,
                force: get_b("force").unwrap_or(false),
            })
        }
        "enable" => {
            let name = get_s("name").ok_or_else(|| "missing param: name".to_string())?;
            Ok(Request::Enable { name })
        }
        "disable" => {
            let name = get_s("name").ok_or_else(|| "missing param: name".to_string())?;
            Ok(Request::Disable { name })
        }
        "flag" => {
            let name = get_s("name").ok_or_else(|| "missing param: name".to_string())?;
            let flags_val = obj.get("flags").cloned().unwrap_or(serde_json::Value::Null);
            let flags: Vec<String> = match flags_val {
                serde_json::Value::String(s) => s
                    .split(',')
                    .map(|x| x.trim().to_ascii_lowercase())
                    .filter(|x| !x.is_empty())
                    .collect(),
                serde_json::Value::Array(a) => a
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(|x| x.trim().to_ascii_lowercase())
                    .filter(|x| !x.is_empty())
                    .collect(),
                _ => vec![],
            };
            if flags.is_empty() {
                return Err("missing/empty param: flags".to_string());
            }
            let ttl = get_s("ttl");
            Ok(Request::Flag { name, flags, ttl })
        }
        "unflag" => {
            let name = get_s("name").ok_or_else(|| "missing param: name".to_string())?;
            let flags_val = obj.get("flags").cloned().unwrap_or(serde_json::Value::Null);
            let flags: Vec<String> = match flags_val {
                serde_json::Value::String(s) => s
                    .split(',')
                    .map(|x| x.trim().to_ascii_lowercase())
                    .filter(|x| !x.is_empty())
                    .collect(),
                serde_json::Value::Array(a) => a
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(|x| x.trim().to_ascii_lowercase())
                    .filter(|x| !x.is_empty())
                    .collect(),
                _ => vec![],
            };
            if flags.is_empty() {
                return Err("missing/empty param: flags".to_string());
            }
            Ok(Request::Unflag { name, flags })
        }
        _ => Err(format!("unknown method: {method}")),
    }
}

async fn serve(
    cfg: WebConsoleConfig,
    addr: SocketAddr,
    app: Router,
    shutting_down: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    crate::pm::daemon::pm_event(
        "web",
        None,
        format!(
            "web_console starting bind={} port={} tls={} mtls={}",
            cfg.bind, cfg.port, cfg.tls.enabled, cfg.tls.mtls
        ),
    );

    if !cfg.tls.enabled {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let shutdown = async move {
            while !shutting_down.load(Ordering::Relaxed) {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        };
        axum::serve(listener, app).with_graceful_shutdown(shutdown).await?;
        return Ok(());
    }

    async fn ensure_tls_material(cfg: &WebConsoleConfig) -> anyhow::Result<(String, String, String)> {
        let ca = cfg
            .tls
            .ca_pem
            .clone()
            .unwrap_or_else(|| "./ca.pem".to_string());
        let cert = cfg
            .tls
            .server_cert_pem
            .clone()
            .unwrap_or_else(|| "./server.pem".to_string());
        let key = cfg
            .tls
            .server_key_pem
            .clone()
            .unwrap_or_else(|| "./server.key".to_string());

        let ca_exists = tokio::fs::try_exists(&ca).await.unwrap_or(false);
        let cert_exists = tokio::fs::try_exists(&cert).await.unwrap_or(false);
        let key_exists = tokio::fs::try_exists(&key).await.unwrap_or(false);

        if !ca_exists && !cert_exists && !key_exists {
            crate::pm::daemon::pm_event(
                "web",
                None,
                format!(
                    "web_console tls_autogen requested (missing all files) ca={} cert={} key={}",
                    ca, cert, key
                ),
            );

            // Generate a CA and server cert signed by it.
            let now = OffsetDateTime::now_utc();
            let not_before = now - TimeDuration::days(3);
            let not_after = now + TimeDuration::days(365 * 20);

            let (ca_pem, server_leaf_pem, server_key_pem) = {
                use rcgen::{
                    BasicConstraints, CertificateParams, DnType, DistinguishedName, ExtendedKeyUsagePurpose, IsCa,
                    KeyPair, SanType,
                };

                let ca_key = KeyPair::generate().map_err(|e| anyhow::anyhow!("failed to generate ca key: {e}"))?;
                let mut ca_params = CertificateParams::default();
                ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                ca_params.not_before = not_before;
                ca_params.not_after = not_after;
                ca_params.distinguished_name = {
                    let mut dn = DistinguishedName::new();
                    dn.push(DnType::CommonName, "processmaster-ca");
                    dn
                };
                let ca_cert = ca_params
                    .self_signed(&ca_key)
                    .map_err(|e| anyhow::anyhow!("failed to self-sign ca cert: {e}"))?;

                let server_key = KeyPair::generate().map_err(|e| anyhow::anyhow!("failed to generate server key: {e}"))?;

                // Build SANs (normalized): DNS is lowercased and deduped; IPs are deduped.
                let mut dns_set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
                let mut ip_set: std::collections::BTreeSet<IpAddr> = std::collections::BTreeSet::new();

                dns_set.insert("localhost".to_string());
                ip_set.insert(IpAddr::from([127, 0, 0, 1]));
                ip_set.insert(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));

                // Optional extra host SAN for operator-provided hostname/IP (e.g. public domain).
                if let Some(raw) = cfg.tls.client_host.as_deref() {
                    let t = raw.trim();
                    if !t.is_empty() {
                        let norm = t.to_ascii_lowercase();
                        let norm = norm.trim();
                        if let Ok(ip) = norm.parse::<IpAddr>() {
                            ip_set.insert(ip);
                        } else {
                            dns_set.insert(norm.to_string());
                        }
                    }
                }

                let dns_names: Vec<String> = dns_set.into_iter().collect();

                let mut server_params = CertificateParams::new(dns_names)
                    .map_err(|e| anyhow::anyhow!("failed to build server cert params: {e}"))?;
                for ip in ip_set {
                    server_params.subject_alt_names.push(SanType::IpAddress(ip));
                }
                // Support both server and client auth (mTLS scenarios) per operator request.
                server_params.extended_key_usages = vec![
                    ExtendedKeyUsagePurpose::ServerAuth,
                    ExtendedKeyUsagePurpose::ClientAuth,
                ];
                server_params.not_before = not_before;
                server_params.not_after = not_after;
                server_params.distinguished_name = {
                    let mut dn = DistinguishedName::new();
                    dn.push(DnType::CommonName, "test");
                    dn
                };
                let server_cert = server_params
                    .signed_by(&server_key, &ca_cert, &ca_key)
                    .map_err(|e| anyhow::anyhow!("failed to sign server cert: {e}"))?;

                (ca_cert.pem(), server_cert.pem(), server_key.serialize_pem())
            };
            // rustls expects the server "cert file" to contain the full chain (leaf first).
            // Including the CA here also makes inspection tools show the issuer chain.
            let server_chain_pem = format!("{server_leaf_pem}\n{ca_pem}");

            async fn write_file(path: &str, contents: &str) -> anyhow::Result<()> {
                let p = Path::new(path);
                if let Some(parent) = p.parent() {
                    if !parent.as_os_str().is_empty() {
                        tokio::fs::create_dir_all(parent).await?;
                    }
                }
                tokio::fs::write(p, contents.as_bytes()).await?;
                Ok(())
            }

            write_file(&ca, &ca_pem).await?;
            write_file(&cert, &server_chain_pem).await?;
            write_file(&key, &server_key_pem).await?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600));
            }

            crate::pm::daemon::pm_event(
                "web",
                None,
                format!(
                    "web_console tls_autogen complete ca={} cert={} key={} cn=test san=localhost,127.0.0.1 valid_years=20 not_before_days_ago=3",
                    ca, cert, key
                ),
            );
        } else if !(ca_exists && cert_exists && key_exists) {
            let mut missing: Vec<&str> = vec![];
            if !ca_exists {
                missing.push("ca_pem");
            }
            if !cert_exists {
                missing.push("server_cert_pem");
            }
            if !key_exists {
                missing.push("server_key_pem");
            }
            anyhow::bail!(
                "web_console tls is enabled but some PEM files are missing: missing={:?} (paths: ca={}, cert={}, key={}). If all three are missing, processmaster will auto-generate a self-signed setup.",
                missing,
                ca,
                cert,
                key
            );
        }

        Ok((ca, cert, key))
    }

    let (ca, cert, key) = ensure_tls_material(&cfg).await?;

    // For now, treat these as file paths.
    let tls_config = if !cfg.tls.mtls {
        axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?
    } else {
        let cert_bytes = tokio::fs::read(&cert).await?;
        let key_bytes = tokio::fs::read(&key).await?;
        let ca_bytes = tokio::fs::read(&ca).await?;

        let mut cert_reader: &[u8] = &cert_bytes;
        let mut key_reader: &[u8] = &key_bytes;
        let mut ca_reader: &[u8] = &ca_bytes;

        let cert_chain: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
        anyhow::ensure!(
            !cert_chain.is_empty(),
            "web_console.tls.server_cert_pem contains no certificates"
        );

        let key_opt: Option<PrivateKeyDer<'static>> = rustls_pemfile::private_key(&mut key_reader)?;
        let key = key_opt.ok_or_else(|| anyhow::anyhow!("web_console.tls.server_key_pem contains no private key"))?;

        let ca_certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut ca_reader).collect::<Result<Vec<_>, _>>()?;
        anyhow::ensure!(
            !ca_certs.is_empty(),
            "web_console.tls.ca_pem contains no certificates"
        );

        let mut roots = rustls::RootCertStore::empty();
        for c in ca_certs {
            roots.add(c)?;
        }

        let verifier = rustls::server::WebPkiClientVerifier::builder(roots.into())
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build mTLS verifier: {e}"))?;

        let server_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(cert_chain, key)
            .map_err(|e| anyhow::anyhow!("failed to build tls config: {e}"))?;

        axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server_config))
    };
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}


