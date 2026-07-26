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
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::process::Command;

#[derive(Clone)]
struct WebState {
    daemon: Arc<Mutex<DaemonState>>,
    users: Arc<HashMap<String, String>>, // username -> bcrypt hash
    auth_cache: Arc<Mutex<AuthCache>>,
    auth_failures: Arc<Mutex<AuthFailureLimiter>>,
    tls_enabled: bool,
}

struct AuthCache {
    // Cache only SUCCESSFUL authentications, one per user (per current stored hash).
    // This avoids unbounded growth from caching failures.
    entries: HashMap<String, CachedAuth>,
    order: VecDeque<String>,
}

struct CachedAuth {
    expected_hash: String,
    digest: u128,
    inserted: Instant,
}

impl AuthCache {
    const MAX_ENTRIES: usize = 1024;
    // A cached entry outlives a password change until it expires, so keep the window
    // short enough that revoking a credential takes effect on its own.
    const TTL: Duration = Duration::from_secs(600);

    fn new() -> Self {
        Self { entries: HashMap::new(), order: VecDeque::new() }
    }

    fn is_cached_ok(&mut self, user: &str, expected_hash: &str, digest: u128, now: Instant) -> bool {
        let Some(e) = self.entries.get(user) else {
            return false;
        };
        if now.duration_since(e.inserted) >= Self::TTL {
            self.entries.remove(user);
            return false;
        }
        e.expected_hash == expected_hash && ct_eq_u128(e.digest, digest)
    }

    fn put_ok(&mut self, user: String, expected_hash: String, digest: u128, now: Instant) {
        if !self.entries.contains_key(&user) {
            self.order.push_back(user.clone());
        }
        self.entries.insert(user, CachedAuth { expected_hash, digest, inserted: now });
        while self.entries.len() > Self::MAX_ENTRIES {
            if let Some(k) = self.order.pop_front() {
                self.entries.remove(&k);
            } else {
                break;
            }
        }
    }
}

// ---------------- password digests (cache keys) ----------------

/// Random per-process key for `password_digest`. Generated once, never written anywhere,
/// and gone when the daemon exits, so a leaked config file or log can never be used to
/// pre-compute digests offline.
fn password_digest_key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut k = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut k);
        k
    })
}

/// Keyed 128-bit digest of a password, used as the auth-cache key so the plaintext is
/// never resident in the daemon's address space.
///
/// The construction is two independently-seeded FNV-1a lanes over (key || password ||
/// length), and the honest tradeoff is this: FNV is not a cryptographic hash and is not
/// memory-hard, so someone who can already dump this process's memory gets the key too
/// and could grind weak passwords offline. What it buys is that the literal password is
/// no longer sitting in a core dump or readable via /proc/pid/mem — which is the actual
/// reported exposure. The authoritative credential store on disk remains bcrypt; bcrypt
/// here would cost ~100ms on every cache *hit*, which is precisely what the cache exists
/// to avoid, and no other hash is available without taking a new dependency.
fn password_digest(pass: &str) -> u128 {
    keyed_digest(password_digest_key(), pass.as_bytes())
}

fn keyed_digest(key: &[u8; 32], pass: &[u8]) -> u128 {
    // Mixing the length in stops "key || a" and "key || b" colliding through padding.
    let len = (pass.len() as u64).to_le_bytes();
    let lo = fnv1a64(0xcbf2_9ce4_8422_2325, key, pass, &len, false);
    let hi = fnv1a64(0x9e37_79b9_7f4a_7c15, key, pass, &len, true);
    ((hi as u128) << 64) | lo as u128
}

fn fnv1a64(seed: u64, key: &[u8], pass: &[u8], len: &[u8], reverse: bool) -> u64 {
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = seed;
    let mut step = |b: u8| {
        h ^= b as u64;
        h = h.wrapping_mul(PRIME);
    };
    // The second lane walks the password backwards so the two lanes are not simple
    // affine transforms of each other; otherwise the extra 64 bits add nothing.
    if reverse {
        for &b in key.iter().rev() {
            step(b);
        }
        for &b in pass.iter().rev() {
            step(b);
        }
    } else {
        for &b in key.iter() {
            step(b);
        }
        for &b in pass.iter() {
            step(b);
        }
    }
    for &b in len {
        step(b);
    }
    h
}

/// Constant-time compare of two digests: a cache hit must not leak, via timing, how many
/// leading bits of a guessed password's digest were right.
fn ct_eq_u128(a: u128, b: u128) -> bool {
    (a ^ b) == 0
}

/// Best-effort wipe of a buffer that held credentials.
///
/// `write_volatile` because a plain loop is a dead store the optimiser may delete. This
/// only removes the copy we control: the allocator may have reused pages, and the raw
/// base64 still lives in the request's HeaderMap until axum drops it.
fn zero_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
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

    let bind_addr: SocketAddr = match crate::pm::config::parse_bind_addr(&cfg.bind, cfg.port) {
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

    if plaintext_remote_refused(cfg.tls.enabled, &bind_addr, cfg.allow_plaintext_remote) {
        crate::pm::daemon::pm_event(
            "web",
            None,
            format!(
                "web_console disabled: refusing to serve basic auth in cleartext on non-loopback \
                 bind={} port={}. This console can run admin_actions as root and HTTP basic auth \
                 only base64-encodes the password, so anyone on the path can read it. Fix by one \
                 of: web_console.tls.enabled: true, web_console.bind: 127.0.0.1 (e.g. behind a \
                 local TLS proxy), or web_console.allow_plaintext_remote: true to accept the risk.",
                cfg.bind, cfg.port
            ),
        );
        return;
    }

    let st = WebState {
        daemon: Arc::clone(&state),
        users: Arc::new(users),
        auth_cache: Arc::new(Mutex::new(AuthCache::new())),
        auth_failures: Arc::new(Mutex::new(AuthFailureLimiter::new())),
        tls_enabled: cfg.tls.enabled,
    };

    crate::pm::daemon::tasks().spawn(async move {
        let app = build_router(st);
        if let Err(e) = serve(cfg, bind_addr, app, shutting_down).await {
            crate::pm::daemon::pm_event("web", None, format!("web_console stopped: {e}"));
        }
    });
}

/// Whether this bind/TLS combination would put console credentials on the wire in the
/// clear against the operator's wishes.
///
/// Loopback is exempt because the packets never leave the host (127.0.0.0/8 and ::1 are
/// both covered by `is_loopback`), and a wildcard bind such as `0.0.0.0` is *not*
/// loopback — it is reachable from the network, which is exactly the dangerous case.
fn plaintext_remote_refused(tls_enabled: bool, addr: &SocketAddr, allow_plaintext_remote: bool) -> bool {
    !tls_enabled && !addr.ip().is_loopback() && !allow_plaintext_remote
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
        .route("/static/app.css", get(static_app_css))
        .route("/static/bootstrap.css", get(vendor_bootstrap_css))
        .route("/static/bootstrap.bundle.js", get(vendor_bootstrap_js))
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

// CSS/JS are embedded rather than loaded from a CDN. processmaster supervises
// servers, and those are routinely air-gapped or egress-filtered — pulling Bootstrap
// over the network meant the console rendered as unstyled HTML exactly where it is
// needed most. Embedding also removes a third-party origin from a root-privileged UI.
const VENDOR_BOOTSTRAP_CSS: &[u8] = include_bytes!("../../templates/vendor/bootstrap.min.css");
const VENDOR_BOOTSTRAP_JS: &[u8] = include_bytes!("../../templates/vendor/bootstrap.bundle.min.js");
const APP_CSS: &[u8] = include_bytes!("../../templates/app.css");

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

async fn vendor_bootstrap_css() -> AxumResponse {
    bytes_response("text/css; charset=utf-8", VENDOR_BOOTSTRAP_CSS)
}

async fn vendor_bootstrap_js() -> AxumResponse {
    bytes_response("text/javascript; charset=utf-8", VENDOR_BOOTSTRAP_JS)
}

async fn static_app_css() -> AxumResponse {
    bytes_response("text/css; charset=utf-8", APP_CSS)
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

// The authenticated username for the current request, handed to handlers via a request
// extension so state-changing RPCs can name an actor in the audit trail.
#[derive(Clone)]
struct Principal(String);

// Failed logins have to be visible, but they are also attacker-triggered: a password
// spray at a few hundred requests/second would otherwise flush every other event out of
// the bounded in-memory event ring, hiding whatever the attacker did next. So log the
// first few failures from a source verbatim, then collapse the rest into at most one
// event per quiet period, carrying the suppressed count so nothing is silently dropped.
const AUTH_FAIL_BURST: u64 = 3;
const AUTH_FAIL_QUIET: Duration = Duration::from_secs(60);
// Bounded like AuthCache: an attacker with many source addresses must not be able to
// grow this map without limit.
const AUTH_FAIL_MAX_SOURCES: usize = 256;

struct AuthFailureLimiter {
    sources: HashMap<String, AuthFailureState>,
    order: VecDeque<String>,
}

struct AuthFailureState {
    /// Failures seen from this source since the last event we emitted for it.
    suppressed: u64,
    emitted: u64,
    last_emit: Instant,
}

impl AuthFailureLimiter {
    fn new() -> Self {
        Self { sources: HashMap::new(), order: VecDeque::new() }
    }

    /// Records one failure. Returns `Some(suppressed)` when the caller should emit an
    /// event, where `suppressed` is how many failures were folded into it.
    fn note(&mut self, source: &str, now: Instant) -> Option<u64> {
        if !self.sources.contains_key(source) {
            self.order.push_back(source.to_string());
            self.sources.insert(
                source.to_string(),
                AuthFailureState { suppressed: 0, emitted: 0, last_emit: now },
            );
            while self.sources.len() > AUTH_FAIL_MAX_SOURCES {
                match self.order.pop_front() {
                    Some(k) => {
                        self.sources.remove(&k);
                    }
                    None => break,
                }
            }
        }
        let st = self.sources.get_mut(source)?;
        if st.emitted < AUTH_FAIL_BURST || now.duration_since(st.last_emit) >= AUTH_FAIL_QUIET {
            let suppressed = st.suppressed;
            st.suppressed = 0;
            st.emitted += 1;
            st.last_emit = now;
            return Some(suppressed);
        }
        st.suppressed += 1;
        None
    }
}

/// Client address for logging only.
///
/// Deliberately reads just the TCP peer from `ConnectInfo` and never `X-Forwarded-For` /
/// `X-Real-IP`: those are caller-supplied and would let an attacker attribute their own
/// failures to someone else's address, or evade the per-source rate limit by rotating a
/// header. Behind a reverse proxy this correctly reports the proxy.
fn client_ip(req: &axum::http::Request<axum::body::Body>) -> String {
    req.extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

async fn basic_auth_middleware(
    State(st): State<WebState>,
    mut req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> impl IntoResponse {
    let headers = req.headers().clone();
    match check_basic_auth(&st.users, &st.auth_cache, &headers).await {
        Ok(user) => {
            req.extensions_mut().insert(Principal(user));
            next.run(req).await
        }
        Err(denied) => {
            let ip = client_ip(&req);
            // A request with no Authorization header at all is the ordinary browser
            // challenge handshake, not an attempt at anything -- logging it would bury
            // the real rejections under one line per first page load.
            let emit = if denied.attempted {
                st.auth_failures
                    .lock()
                    .ok()
                    .and_then(|mut l| l.note(&ip, Instant::now()))
            } else {
                None
            };
            if let Some(suppressed) = emit {
                crate::pm::daemon::pm_event(
                    "web",
                    None,
                    format!(
                        "auth_failure ip={} user={} reason={} suppressed_since_last={}",
                        ip,
                        denied.known_user.as_deref().unwrap_or("-"),
                        denied.client_message,
                        suppressed
                    ),
                );
            }
            (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, r#"Basic realm="processmaster""#)],
                denied.client_message,
            )
                .into_response()
        }
    }
}

struct AuthDenied {
    /// Returned to the client and used as the logged reason; a fixed set of strings.
    client_message: String,
    /// Only ever set to a *configured* username. The submitted username is attacker
    /// controlled and must not reach the event ring, where it would be read as trusted
    /// operator-facing text (and could carry newlines or a password typed in the wrong
    /// field). Unknown usernames therefore log as "-".
    known_user: Option<String>,
    /// False only when the request carried no credentials at all.
    attempted: bool,
}

impl AuthDenied {
    /// A rejected attempt whose username is not one we know.
    fn anonymous(msg: &str) -> Self {
        Self { client_message: msg.to_string(), known_user: None, attempted: true }
    }
    fn for_user(user: &str, msg: &str) -> Self {
        Self { client_message: msg.to_string(), known_user: Some(user.to_string()), attempted: true }
    }
    /// No Authorization header: the client is being challenged, not refused.
    fn unchallenged(msg: &str) -> Self {
        Self { client_message: msg.to_string(), known_user: None, attempted: false }
    }
}

// bcrypt hash of a fixed throwaway password, generated at bcrypt::DEFAULT_COST.
// Verified against when the username is unknown so that unknown and known users cost
// the same wall-clock time (otherwise the response time enumerates valid usernames).
const DUMMY_BCRYPT_HASH: &str = "$2b$12$BZCGuMAbOe5rXqoieAs5aOxvCRLsq5VaFUSiKk/7xlEM305d63GN6";

/// Returns the authenticated username on success.
async fn check_basic_auth(
    users: &HashMap<String, String>,
    auth_cache: &Arc<Mutex<AuthCache>>,
    headers: &axum::http::HeaderMap,
) -> Result<String, AuthDenied> {
    let Some(v) = headers.get(header::AUTHORIZATION) else {
        return Err(AuthDenied::unchallenged("missing Authorization header"));
    };
    let Ok(s) = v.to_str() else {
        return Err(AuthDenied::anonymous("invalid Authorization header"));
    };
    let s = s.trim();
    let Some(b64) = s.strip_prefix("Basic ").or_else(|| s.strip_prefix("basic ")) else {
        return Err(AuthDenied::anonymous("expected Basic authorization"));
    };
    let mut decoded = BASE64
        .decode(b64.trim().as_bytes())
        .map_err(|_| AuthDenied::anonymous("invalid base64 in Authorization"))?;
    // Wipe the decoded "user:pass" as soon as the verdict is in, so the plaintext is not
    // left lying in the heap for a core dump to pick up (see FIX 3 / password_digest).
    let out = check_decoded_basic_auth(users, auth_cache, &decoded).await;
    zero_bytes(&mut decoded);
    out
}

async fn check_decoded_basic_auth(
    users: &HashMap<String, String>,
    auth_cache: &Arc<Mutex<AuthCache>>,
    decoded: &[u8],
) -> Result<String, AuthDenied> {
    let Ok(s) = std::str::from_utf8(decoded) else {
        return Err(AuthDenied::anonymous("invalid utf8 in Authorization"));
    };
    let Some((user, pass)) = s.split_once(':') else {
        return Err(AuthDenied::anonymous("invalid basic auth payload"));
    };
    let Some(expected_hash) = users.get(user).cloned() else {
        // Unknown user: burn an equivalent bcrypt verify so the reply time does not
        // reveal whether the username exists, then fail with the same message.
        let _ = bcrypt_verify_blocking(pass, DUMMY_BCRYPT_HASH).await;
        return Err(AuthDenied::anonymous("invalid credentials"));
    };

    // Cache lookup: if this (user, hash, password digest) succeeded before, accept
    // immediately and skip bcrypt.
    let digest = password_digest(pass);
    if let Ok(mut c) = auth_cache.lock() {
        if c.is_cached_ok(user, &expected_hash, digest, Instant::now()) {
            return Ok(user.to_string());
        }
    }

    // Cache miss: verify once.
    let ok = bcrypt_verify_blocking(pass, &expected_hash).await;
    if !ok {
        return Err(AuthDenied::for_user(user, "invalid credentials"));
    }
    // Successful verify: remember it (best-effort).
    if let Ok(mut c) = auth_cache.lock() {
        c.put_ok(user.to_string(), expected_hash, digest, Instant::now());
    }
    Ok(user.to_string())
}

// bcrypt is deliberately CPU-expensive and this daemon shares ONE tokio runtime with
// all supervision work, so a burst of logins on the async workers would starve it.
// Always verify on the blocking pool. Any error (bad hash, join failure) is a mismatch.
async fn bcrypt_verify_blocking(pass: &str, hash: &str) -> bool {
    let pass = pass.to_string();
    let hash = hash.to_string();
    matches!(
        tokio::task::spawn_blocking(move || bcrypt::verify(&pass, &hash)).await,
        Ok(Ok(true))
    )
}

// ---------------- CSRF ----------------

const CSRF_COOKIE: &str = "pm_csrf";
const CSRF_HEADER: &str = "x-csrf-token";

// The CSRF token for the current request, handed to handlers via a request extension so
// the status page can render a token even on the very first load (before any cookie).
#[derive(Clone)]
struct CsrfToken(String);

// Constant-time comparison, so a wrong token cannot be recovered byte-by-byte via
// timing. Length mismatch is not secret (the token length is fixed), so it fails fast.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn csrf_middleware(
    State(st): State<WebState>,
    mut req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> impl IntoResponse {
    // NOTE: this layer lives inside `.nest("/processmaster", ..)`, so the path observed
    // here is already prefix-stripped -- matching on a mounted path would never fire.
    // Enforce on METHOD instead: every unsafe method must carry X-CSRF-Token == cookie.
    let method = req.method().clone();
    let headers = req.headers().clone();

    let safe_method = matches!(
        method,
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    );

    let cookie_token = cookie_get(&headers, CSRF_COOKIE);
    if !safe_method {
        let hdr = headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok()).map(|s| s.trim());
        let ok = match (cookie_token.as_deref(), hdr) {
            (Some(c), Some(h)) => !c.is_empty() && ct_eq(c, h),
            _ => false,
        };
        if !ok {
            return (StatusCode::FORBIDDEN, "csrf check failed").into_response();
        }
    }

    // Mint the token up front (not just on the response) so the first page load already
    // renders it into <meta name="csrf-token">, and set that same value as the cookie.
    let (token, fresh) = match cookie_token {
        Some(t) if !t.is_empty() => (t, false),
        _ => (new_csrf_token(), true),
    };
    req.extensions_mut().insert(CsrfToken(token.clone()));

    let mut resp = next.run(req).await;

    if fresh && safe_method {
        let mut cookie = format!("{CSRF_COOKIE}={token}; Path=/processmaster/; SameSite=Strict");
        if st.tls_enabled {
            cookie.push_str("; Secure");
        }
        cookie.push_str("; HttpOnly");
        resp.headers_mut()
            .append(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
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

async fn status_page(
    State(_st): State<WebState>,
    axum::Extension(CsrfToken(token)): axum::Extension<CsrfToken>,
) -> AxumResponse {
    // The token comes from csrf_middleware (cookie value, or freshly minted on first
    // load) so the rendered <meta> tag is never empty.
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
        // Compact stamp: the navbar already carries the product name.
        build_banner: crate::pm::build_info::short_stamp(),
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

/// Describes the target of a state-changing RPC, or `None` for read-only ones.
///
/// The console polls status/events/logs/details every few seconds per open tab, so
/// logging those would bury the audit trail in the bounded event ring within seconds.
/// Unknown methods are read-only by construction: they are rejected before dispatch.
fn audit_target(method: &str, params: &serde_json::Value) -> Option<String> {
    let p = |k: &str| params.get(k).and_then(|v| v.as_str()).unwrap_or("");
    match method {
        // processmaster services
        "start" | "stop" | "restart" | "enable" | "disable" | "flag" | "unflag" => {
            Some(format!("target={}", sanitize_event_field(p("name"))))
        }
        "admin_action" => Some(format!("admin_action={}", sanitize_event_field(p("name")))),
        "start_all" | "stop_all" | "restart_all" | "update" => Some("target=<all>".to_string()),
        // host systemd units and the admin_actions cgroup
        "systemd_action" => Some(format!(
            "unit={} systemd_action={}",
            sanitize_event_field(p("unit")),
            sanitize_event_field(p("action"))
        )),
        "admin_actions_kill" => Some("target=<admin_actions cgroup>".to_string()),
        _ => None,
    }
}

/// Makes a client-supplied string safe to place in an operator-facing event line.
///
/// The event ring is line-oriented and read by humans, so a request parameter must not
/// be able to inject a newline (forging a second event) or run to an unbounded length.
fn sanitize_event_field(s: &str) -> String {
    let t = s.trim();
    if t.is_empty() {
        return "-".to_string();
    }
    let cleaned: String = t
        .chars()
        .take(64)
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .collect();
    if t.chars().count() > 64 {
        format!("{cleaned}...")
    } else {
        cleaned
    }
}

async fn jsonrpc(
    State(st): State<WebState>,
    principal: Option<axum::Extension<Principal>>,
    Json(req): Json<JsonRpcRequest>,
) -> impl IntoResponse {
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

    // Audit trail: record *who* asked for every state change, before doing it, so an
    // action that hangs or crashes the daemon is still attributed.
    if let Some(target) = audit_target(&req.method, &req.params) {
        // `Principal` is inserted by basic_auth_middleware, which no request reaches
        // this handler without; "-" would mean that invariant broke.
        let actor = principal
            .as_ref()
            .map(|axum::Extension(Principal(u))| u.as_str())
            .unwrap_or("-");
        crate::pm::daemon::pm_event(
            "web",
            None,
            format!("rpc_invoke actor={actor} method={} {target}", req.method),
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
        "systemd_list" => {
            let resp = match systemd_list_services().await {
                Ok(v) => serde_json::json!({ "ok": true, "message": "", "services": v }),
                Err(e) => serde_json::json!({ "ok": false, "message": e.to_string(), "services": [] }),
            };
            return (
                StatusCode::OK,
                Json(JsonRpcResponse::<serde_json::Value> {
                    jsonrpc: "2.0",
                    id: req.id,
                    result: Some(resp),
                    error: None,
                }),
            );
        }
        "systemd_action" => {
            let unit = req
                .params
                .get("unit")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            let action = req
                .params
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if unit.is_empty() || action.is_empty() {
                let v = serde_json::json!({ "ok": false, "message": "missing/empty params: unit/action" });
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
            let resp = match systemd_action(&unit, &action).await {
                Ok(msg) => serde_json::json!({ "ok": true, "message": msg }),
                Err(e) => serde_json::json!({ "ok": false, "message": e.to_string() }),
            };
            return (
                StatusCode::OK,
                Json(JsonRpcResponse::<serde_json::Value> {
                    jsonrpc: "2.0",
                    id: req.id,
                    result: Some(resp),
                    error: None,
                }),
            );
        }
        "systemd_logs" => {
            let unit = req
                .params
                .get("unit")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            let n = req
                .params
                .get("n")
                .and_then(|v| v.as_u64())
                .map(|x| x as usize)
                .unwrap_or(200);
            if unit.is_empty() {
                let v = serde_json::json!({ "ok": false, "message": "missing/empty param: unit" });
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
            let resp = match systemd_logs(&unit, n).await {
                Ok(text) => serde_json::json!({ "ok": true, "message": text }),
                Err(e) => serde_json::json!({ "ok": false, "message": e.to_string() }),
            };
            return (
                StatusCode::OK,
                Json(JsonRpcResponse::<serde_json::Value> {
                    jsonrpc: "2.0",
                    id: req.id,
                    result: Some(resp),
                    error: None,
                }),
            );
        }
        "systemd_service_details" => {
            let unit = req
                .params
                .get("unit")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if unit.is_empty() {
                let v = serde_json::json!({ "ok": false, "message": "missing/empty param: unit" });
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
            let unit_ok = unit.clone();
            let resp = match systemd_service_details(&unit).await {
                Ok((cg, snap)) => serde_json::json!({
                    "ok": true,
                    "message": "",
                    "unit": unit_ok,
                    "cgroup_dir": cg.display().to_string(),
                    "snapshot": snap,
                }),
                Err(e) => serde_json::json!({ "ok": false, "message": e.to_string(), "unit": unit }),
            };
            return (
                StatusCode::OK,
                Json(JsonRpcResponse::<serde_json::Value> {
                    jsonrpc: "2.0",
                    id: req.id,
                    result: Some(resp),
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

// ---------------- systemd helpers (web console) ----------------

#[derive(Debug, Clone, serde::Serialize)]
struct SystemdServiceStatus {
    unit: String,
    phase: String, // RUNNING/STOPPED
    enabled: bool,
    unit_file_state: String,
    fragment_path: String,
    exec_start_path: String,
    main_pid: i32,
    cgroup_dir: String,
    pids: Vec<u32>,
    pid_uptimes_ms: Vec<i64>,
}

fn validate_systemd_unit(unit: &str) -> anyhow::Result<()> {
    let t = unit.trim();
    anyhow::ensure!(!t.is_empty(), "unit is empty");
    anyhow::ensure!(t.ends_with(".service"), "only .service units are supported (got {t:?})");
    anyhow::ensure!(
        t.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@' | ':' | '\\')),
        "invalid unit name (unsupported characters): {t:?}"
    );
    Ok(())
}

fn validate_systemd_action(action: &str) -> anyhow::Result<&'static str> {
    match action {
        "start" => Ok("start"),
        "stop" => Ok("stop"),
        "restart" => Ok("restart"),
        _ => anyhow::bail!("unsupported action: {action:?} (allowed: start|stop|restart)"),
    }
}

async fn run_cmd_timeout(mut cmd: Command, ms: u64) -> anyhow::Result<std::process::Output> {
    let fut = cmd.output();
    let out = tokio::time::timeout(std::time::Duration::from_millis(ms), fut)
        .await
        .map_err(|_| anyhow::anyhow!("command timed out after {ms}ms"))??;
    Ok(out)
}

fn sysfs_cgroup_dir_from_control_group(control_group: &str) -> Option<PathBuf> {
    let cg = control_group.trim();
    if cg.is_empty() {
        return None;
    }
    // systemctl show ControlGroup is typically like "/system.slice/sshd.service"
    let rel = cg.trim_start_matches('/');
    if rel.is_empty() {
        return None;
    }
    Some(PathBuf::from("/sys/fs/cgroup").join(rel))
}

fn clock_ticks_per_second() -> Option<f64> {
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if v <= 0 { None } else { Some(v as f64) }
}

fn read_system_uptime_seconds() -> Option<f64> {
    let s = std::fs::read_to_string("/proc/uptime").ok()?;
    let first = s.split_whitespace().next()?;
    first.parse::<f64>().ok()
}

fn compute_pid_uptimes_ms_u32(pids: &[u32], sys_uptime_s: Option<f64>, hz: Option<f64>) -> Vec<i64> {
    let mut out = Vec::with_capacity(pids.len());
    for &pid in pids {
        let ms = pid_uptime_ms_u32(pid, sys_uptime_s, hz);
        out.push(ms.unwrap_or(-1));
    }
    out
}

fn pid_uptime_ms_u32(pid: u32, sys_uptime_s: Option<f64>, hz: Option<f64>) -> Option<i64> {
    let sys_uptime_s = sys_uptime_s?;
    let hz = hz?;
    let start_ticks = read_pid_starttime_ticks_u32(pid)?;
    let started_s = (start_ticks as f64) / hz;
    let up_s = (sys_uptime_s - started_s).max(0.0);
    Some((up_s * 1000.0).round() as i64)
}

fn read_pid_starttime_ticks_u32(pid: u32) -> Option<u64> {
    let path = format!("/proc/{pid}/stat");
    let stat = std::fs::read_to_string(path).ok()?;
    let rparen = stat.rfind(')')?;
    let after = stat.get(rparen + 2..)?; // skip ") "
    let fields: Vec<&str> = after.split_whitespace().collect();
    // fields[0] is original field 3 (state). starttime is original field 22 => index 22-3 = 19
    let start = *fields.get(19)?;
    start.parse::<u64>().ok()
}

async fn systemd_list_services() -> anyhow::Result<Vec<SystemdServiceStatus>> {
    // Bulk query for all service units. This is dramatically faster than per-unit `systemctl show`.
    let mut cmd = Command::new("systemctl");
    cmd.arg("show")
        .arg("--type=service")
        .arg("--all")
        .arg("--no-pager")
        .arg("--property=Id,ActiveState,SubState,MainPID,ControlGroup,UnitFileState,FragmentPath,ExecStart");
    let out = run_cmd_timeout(cmd, 3000).await?;

    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        anyhow::bail!("systemctl show failed: {}", if err.is_empty() { out.status.to_string() } else { err });
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let sys_uptime_s = read_system_uptime_seconds();
    let hz = clock_ticks_per_second();

    let mut services = vec![];
    for block in text.split("\n\n") {
        let mut id: Option<String> = None;
        let mut active: Option<String> = None;
        let mut sub: Option<String> = None;
        let mut main_pid: Option<i32> = None;
        let mut cg: Option<String> = None;
        let mut ufs: Option<String> = None;
        let mut frag: Option<String> = None;
        let mut exec_start: Option<String> = None;

        for line in block.lines() {
            let (k, v) = match line.split_once('=') {
                Some(kv) => kv,
                None => continue,
            };
            let v = v.trim().to_string();
            match k.trim() {
                "Id" => id = Some(v),
                "ActiveState" => active = Some(v),
                "SubState" => sub = Some(v),
                "MainPID" => {
                    let p = v.parse::<i32>().unwrap_or(0);
                    main_pid = Some(p);
                }
                "ControlGroup" => cg = Some(v),
                "UnitFileState" => ufs = Some(v),
                "FragmentPath" => frag = Some(v),
                "ExecStart" => exec_start = Some(v),
                _ => {}
            }
        }

        let Some(unit) = id else { continue };
        if !unit.ends_with(".service") {
            continue;
        }
        // Avoid odd corner cases: only list units we can later act on.
        if validate_systemd_unit(&unit).is_err() {
            continue;
        }

        let active_state = active.unwrap_or_else(|| "unknown".to_string());
        let sub_state = sub.unwrap_or_else(|| "".to_string());
        let mpid = main_pid.unwrap_or(0);
        let unit_file_state = ufs.unwrap_or_else(|| "unknown".to_string());
        let fragment_path = frag.unwrap_or_default();
        let exec_start_path = exec_start
            .as_deref()
            .and_then(parse_systemd_execstart_path)
            .unwrap_or_default();
        let enabled = unit_file_state.starts_with("enabled");
        let phase = if active_state == "active" && sub_state == "exited" {
            "EXITED"
        } else if active_state == "active" {
            "RUNNING"
        } else if active_state == "failed" {
            "FAILED"
        } else {
            "STOPPED"
        }
        .to_string();

        let cgroup_dir = cg.clone().unwrap_or_default();
        let sysfs_dir = cg.as_deref().and_then(sysfs_cgroup_dir_from_control_group);
        let pids = match sysfs_dir.as_deref() {
            Some(dir) if std::fs::metadata(dir).is_ok() => cgroup::list_pids(dir).unwrap_or_default(),
            _ => vec![],
        };
        let pid_uptimes_ms = compute_pid_uptimes_ms_u32(&pids, sys_uptime_s, hz);

        services.push(SystemdServiceStatus {
            unit,
            phase,
            enabled,
            unit_file_state,
            fragment_path,
            exec_start_path,
            main_pid: mpid,
            cgroup_dir,
            pids,
            pid_uptimes_ms,
        });
    }

    services.sort_by(|a, b| a.unit.cmp(&b.unit));
    Ok(services)
}

fn parse_systemd_execstart_path(raw: &str) -> Option<String> {
    // `systemctl show -p ExecStart` commonly yields strings like:
    //   ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D ... ; ... }
    // There may be multiple `{...}{...}` entries; we just take the first `path=...`.
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    let idx = t.find("path=")?;
    let rest = &t[idx + "path=".len()..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == ';' || c == '}' || c == ',' )
        .unwrap_or(rest.len());
    let p = rest[..end].trim().trim_matches('"').to_string();
    if p.is_empty() { None } else { Some(p) }
}

async fn systemd_action(unit: &str, action: &str) -> anyhow::Result<String> {
    validate_systemd_unit(unit)?;
    let action = validate_systemd_action(action)?;
    let mut cmd = Command::new("systemctl");
    cmd.arg("--no-pager").arg(action).arg(unit);
    let out = run_cmd_timeout(cmd, 10_000).await?;
    if out.status.success() {
        return Ok(format!("{action} {unit}: ok"));
    }
    let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
    anyhow::bail!(
        "systemctl {} {} failed: {}",
        action,
        unit,
        if err.is_empty() { out.status.to_string() } else { err }
    );
}

async fn systemd_logs(unit: &str, n: usize) -> anyhow::Result<String> {
    validate_systemd_unit(unit)?;
    let n = n.clamp(1, 5000);
    let mut cmd = Command::new("journalctl");
    cmd.arg("-u")
        .arg(unit)
        .arg("-n")
        .arg(n.to_string())
        .arg("--no-pager")
        .arg("--output=short-iso");
    let out = run_cmd_timeout(cmd, 5000).await?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        anyhow::bail!(
            "journalctl -u {unit} failed: {}",
            if err.is_empty() { out.status.to_string() } else { err }
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

async fn systemd_service_details(unit: &str) -> anyhow::Result<(PathBuf, cgroup::CgroupResourceSnapshot)> {
    validate_systemd_unit(unit)?;
    let mut cmd = Command::new("systemctl");
    cmd.arg("show")
        .arg(unit)
        .arg("--no-pager")
        .arg("--property=ControlGroup");
    let out = run_cmd_timeout(cmd, 3000).await?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        anyhow::bail!(
            "systemctl show {unit} failed: {}",
            if err.is_empty() { out.status.to_string() } else { err }
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let cg = text
        .lines()
        .find_map(|line| line.strip_prefix("ControlGroup="))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let dir = sysfs_cgroup_dir_from_control_group(&cg)
        .ok_or_else(|| anyhow::anyhow!("systemd unit has no ControlGroup: {unit}"))?;
    if let Err(e) = std::fs::metadata(&dir) {
        anyhow::bail!("cgroup dir not found for {unit}: {}: {e}", dir.display());
    }
    let snap = cgroup::read_resource_snapshot(&dir)?;
    Ok((dir, snap))
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

// ---------------- auto-generated TLS material ----------------

/// 397 days: the maximum a public CA (and therefore every browser) will accept for a
/// server certificate. A long-lived auto-generated key is a credential nobody rotates.
const AUTOGEN_CERT_VALID_DAYS: i64 = 397;

/// CN of the CA processmaster generates for itself. Doubles as the marker that tells an
/// expired certificate of ours apart from an operator's own.
const AUTOGEN_CA_COMMON_NAME: &str = "processmaster-ca";

/// The host's name, if it is usable as a certificate DNS SAN.
///
/// Read from /proc rather than gethostname(2): this daemon is Linux/cgroup-v2 only, so
/// /proc is always mounted, and it keeps an unsafe call out of the TLS path. Anything
/// that is not a plain DNS label is rejected rather than fed to rcgen.
fn system_hostname() -> Option<String> {
    let raw = std::fs::read_to_string("/proc/sys/kernel/hostname").ok()?;
    let t = raw.trim().to_ascii_lowercase();
    if t.is_empty() || t.len() > 253 {
        return None;
    }
    if !t
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return None;
    }
    Some(t)
}

/// Subject CN for the generated leaf. `CN=test` said nothing about which machine was
/// being talked to, which matters when several hosts each generate their own.
fn autogen_cert_common_name(hostname: Option<&str>) -> String {
    hostname
        .map(|h| h.to_string())
        .unwrap_or_else(|| "processmaster".to_string())
}

/// SANs for the generated leaf, normalized (DNS lowercased, both sets deduped/sorted).
///
/// Modern clients ignore the CN entirely and match on SANs alone, so anything an
/// operator might type into the address bar has to be listed here: loopback, the host's
/// own name, the configured `client_host`, and the address the console actually binds.
/// A wildcard bind (0.0.0.0 / ::) names no particular interface and is skipped -- there
/// is nothing to put in the certificate.
fn autogen_cert_sans(
    client_host: Option<&str>,
    bind_ip: IpAddr,
    hostname: Option<&str>,
) -> (Vec<String>, Vec<IpAddr>) {
    let mut dns_set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut ip_set: std::collections::BTreeSet<IpAddr> = std::collections::BTreeSet::new();

    dns_set.insert("localhost".to_string());
    ip_set.insert(IpAddr::from([127, 0, 0, 1]));
    ip_set.insert(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));

    if let Some(h) = hostname {
        let t = h.trim().to_ascii_lowercase();
        if !t.is_empty() {
            dns_set.insert(t);
        }
    }

    if !bind_ip.is_unspecified() {
        ip_set.insert(bind_ip);
    }

    // Optional extra host SAN for operator-provided hostname/IP (e.g. public domain).
    if let Some(raw) = client_host {
        let t = raw.trim().to_ascii_lowercase();
        if !t.is_empty() {
            if let Ok(ip) = t.parse::<IpAddr>() {
                ip_set.insert(ip);
            } else {
                dns_set.insert(t);
            }
        }
    }

    (dns_set.into_iter().collect(), ip_set.into_iter().collect())
}

enum CertStatus {
    Valid { not_after: OffsetDateTime },
    /// Expired, and issued by the CA processmaster generates: safe to renew in place.
    ExpiredAutogen { not_after: OffsetDateTime },
    /// Expired, but somebody else's: we hold no key that can re-sign it.
    ExpiredForeign { not_after: OffsetDateTime },
    /// Could not be established. Never treat this as "valid" silently.
    Unknown { reason: String },
}

async fn server_cert_status(cert_path: &str, now: OffsetDateTime) -> CertStatus {
    let bytes = match tokio::fs::read(cert_path).await {
        Ok(b) => b,
        Err(e) => return CertStatus::Unknown { reason: format!("cannot read: {e}") },
    };
    let mut reader: &[u8] = &bytes;
    let chain: Vec<CertificateDer<'static>> = match rustls_pemfile::certs(&mut reader).collect() {
        Ok(v) => v,
        Err(e) => return CertStatus::Unknown { reason: format!("cannot parse PEM: {e}") },
    };
    // The leaf comes first by rustls convention; that is the one clients validate.
    let Some(leaf) = chain.first() else {
        return CertStatus::Unknown { reason: "no certificates in file".to_string() };
    };
    let Some((not_after, issuer)) = cert_not_after_and_issuer(leaf.as_ref()) else {
        return CertStatus::Unknown { reason: "unrecognised certificate structure".to_string() };
    };
    if not_after > now {
        return CertStatus::Valid { not_after };
    }
    if issuer
        .windows(AUTOGEN_CA_COMMON_NAME.len())
        .any(|w| w == AUTOGEN_CA_COMMON_NAME.as_bytes())
    {
        CertStatus::ExpiredAutogen { not_after }
    } else {
        CertStatus::ExpiredForeign { not_after }
    }
}

/// Recovers `notAfter` and the raw issuer name from a DER certificate.
///
/// Hand-rolled because neither of our TLS crates can answer this: rustls only checks
/// validity when acting as a *client*, and rcgen only writes certificates. This walks
/// exactly as far into the structure as it must and returns `None` the moment anything
/// is unexpected -- callers must treat that as "unknown", never as "valid".
///
///   Certificate ::= SEQUENCE { tbsCertificate, ... }
///   TBSCertificate ::= SEQUENCE { [0] version OPTIONAL, serialNumber, signature,
///                                 issuer, validity, ... }
///   Validity ::= SEQUENCE { notBefore Time, notAfter Time }
fn cert_not_after_and_issuer(der: &[u8]) -> Option<(OffsetDateTime, &[u8])> {
    const SEQUENCE: u8 = 0x30;
    const CONTEXT_0: u8 = 0xa0;

    let (tag, cert_body, _) = der_take(der)?;
    if tag != SEQUENCE {
        return None;
    }
    let (tag, tbs, _) = der_take(cert_body)?;
    if tag != SEQUENCE {
        return None;
    }
    // version is [0] EXPLICIT and optional (absent means v1).
    let (tag, _, after_version) = der_take(tbs)?;
    let rest = if tag == CONTEXT_0 { after_version } else { tbs };
    let (_, _, rest) = der_take(rest)?; // serialNumber
    let (_, _, rest) = der_take(rest)?; // signature AlgorithmIdentifier
    let (_, issuer, rest) = der_take(rest)?; // issuer Name
    let (tag, validity, _) = der_take(rest)?;
    if tag != SEQUENCE {
        return None;
    }
    let (_, _, after_not_before) = der_take(validity)?;
    let (tag, not_after, _) = der_take(after_not_before)?;
    Some((parse_asn1_time(tag, not_after)?, issuer))
}

/// Splits one DER TLV off the front, returning (tag, contents, remainder).
fn der_take(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = buf.split_first()?;
    let (&len0, rest) = rest.split_first()?;
    let (len, rest) = if len0 < 0x80 {
        (len0 as usize, rest)
    } else {
        // Long form: the low 7 bits give the number of length bytes that follow.
        let n = (len0 & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let mut v = 0usize;
        for &b in &rest[..n] {
            v = (v << 8) | b as usize;
        }
        (v, &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

fn parse_asn1_time(tag: u8, body: &[u8]) -> Option<OffsetDateTime> {
    const UTC_TIME: u8 = 0x17;
    const GENERALIZED_TIME: u8 = 0x18;

    let s = std::str::from_utf8(body).ok()?.trim_end_matches('Z');
    // Only the UTC forms are accepted: an offset form ("...+0200") is legal ASN.1 but
    // forbidden in certificates, and guessing at one would misdate the expiry.
    let (year, rest) = match tag {
        UTC_TIME => {
            let yy: i32 = s.get(0..2)?.parse().ok()?;
            // RFC 5280: two-digit years 00..=49 are 20xx, 50..=99 are 19xx.
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, s.get(2..)?)
        }
        GENERALIZED_TIME => (s.get(0..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    if rest.len() < 10 {
        return None;
    }
    let num = |a: usize, b: usize| -> Option<u8> { rest.get(a..b)?.parse().ok() };
    let month = time::Month::try_from(num(0, 2)?).ok()?;
    let date = time::Date::from_calendar_date(year, month, num(2, 4)?).ok()?;
    Some(
        date.with_hms(num(4, 6)?, num(6, 8)?, num(8, 10)?)
            .ok()?
            .assume_utc(),
    )
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
        // with_connect_info so the auth layer can attribute failed logins to a peer
        // address that the client cannot forge (unlike X-Forwarded-For).
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(shutdown)
            .await?;
        return Ok(());
    }

    async fn ensure_tls_material(
        cfg: &WebConsoleConfig,
        addr: SocketAddr,
    ) -> anyhow::Result<(String, String, String)> {
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

        let mut ca_exists = tokio::fs::try_exists(&ca).await.unwrap_or(false);
        let mut cert_exists = tokio::fs::try_exists(&cert).await.unwrap_or(false);
        let mut key_exists = tokio::fs::try_exists(&key).await.unwrap_or(false);

        // An expired certificate is not a working certificate: every client aborts the
        // handshake and the daemon reports nothing at all. Check before serving.
        if ca_exists && cert_exists && key_exists {
            match server_cert_status(&cert, OffsetDateTime::now_utc()).await {
                CertStatus::Valid { not_after } => {
                    crate::pm::daemon::pm_event(
                        "web",
                        None,
                        format!("web_console tls_cert cert={cert} not_after={not_after}"),
                    );
                }
                CertStatus::ExpiredAutogen { not_after } => {
                    // Ours to replace: the CA private key was never persisted, so the
                    // only way to renew is to regenerate the whole self-signed set.
                    // Keep the old files rather than deleting them, in case an operator
                    // needs to inspect what was being served.
                    let stamp = OffsetDateTime::now_utc().unix_timestamp();
                    for p in [&ca, &cert, &key] {
                        let dst = format!("{p}.expired-{stamp}");
                        tokio::fs::rename(p, &dst).await.map_err(|e| {
                            anyhow::anyhow!("failed to move expired tls material {p} aside: {e}")
                        })?;
                    }
                    ca_exists = false;
                    cert_exists = false;
                    key_exists = false;
                    crate::pm::daemon::pm_event(
                        "web",
                        None,
                        format!(
                            "web_console tls_cert expired not_after={not_after}; the auto-generated \
                             certificate was renewed. Old files kept as *.expired-{stamp}. Clients \
                             that imported the previous CA must import the new {ca}."
                        ),
                    );
                }
                CertStatus::ExpiredForeign { not_after } => {
                    // Not ours: regenerating would swap an operator's real chain for a
                    // self-signed one, which is a downgrade, and we cannot re-sign
                    // against their CA. Refuse loudly instead of serving a dead cert.
                    anyhow::bail!(
                        "web_console.tls.server_cert_pem ({cert}) expired at {not_after} and was not \
                         auto-generated by processmaster. Renew it, or delete ca/cert/key to have a \
                         self-signed set generated."
                    );
                }
                CertStatus::Unknown { reason } => {
                    crate::pm::daemon::pm_event(
                        "web",
                        None,
                        format!(
                            "web_console tls_cert validity_unknown cert={cert}: {reason}. Serving \
                             anyway, but an expired certificate here would fail every handshake -- \
                             check the expiry manually (openssl x509 -enddate -noout -in {cert})."
                        ),
                    );
                }
            }
        }

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
            // 397 days is the maximum lifetime browsers accept for a server certificate,
            // and a short life is what makes a leaked auto-generated key self-limiting.
            // The daemon renews on its own once this lapses (see server_cert_status).
            let not_after = now + TimeDuration::days(AUTOGEN_CERT_VALID_DAYS);
            // The CA must outlive the leaf it signs, or the chain dies early; it is not a
            // public server cert, so the 397-day cap does not apply to it.
            let ca_not_after = now + TimeDuration::days(AUTOGEN_CERT_VALID_DAYS + 30);

            let hostname = system_hostname();
            let common_name = autogen_cert_common_name(hostname.as_deref());
            let (dns_names, ip_addrs) =
                autogen_cert_sans(cfg.tls.client_host.as_deref(), addr.ip(), hostname.as_deref());

            let (ca_pem, server_leaf_pem, server_key_pem) = {
                use rcgen::{
                    BasicConstraints, CertificateParams, DnType, DistinguishedName, ExtendedKeyUsagePurpose, IsCa,
                    KeyPair, SanType,
                };

                let ca_key = KeyPair::generate().map_err(|e| anyhow::anyhow!("failed to generate ca key: {e}"))?;
                let mut ca_params = CertificateParams::default();
                ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                ca_params.not_before = not_before;
                ca_params.not_after = ca_not_after;
                ca_params.distinguished_name = {
                    let mut dn = DistinguishedName::new();
                    // Also the marker server_cert_status looks for when deciding whether
                    // an expired certificate is ours to renew -- keep the two in step.
                    dn.push(DnType::CommonName, AUTOGEN_CA_COMMON_NAME);
                    dn
                };
                let ca_cert = ca_params
                    .self_signed(&ca_key)
                    .map_err(|e| anyhow::anyhow!("failed to self-sign ca cert: {e}"))?;

                let server_key = KeyPair::generate().map_err(|e| anyhow::anyhow!("failed to generate server key: {e}"))?;

                let mut server_params = CertificateParams::new(dns_names.clone())
                    .map_err(|e| anyhow::anyhow!("failed to build server cert params: {e}"))?;
                for ip in ip_addrs.iter().copied() {
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
                    dn.push(DnType::CommonName, common_name.as_str());
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

            // The private key must never be world-readable, not even for the instant
            // between write and chmod: create it 0600 up front. Errors are propagated --
            // silently failing here would leave the key readable by every local user.
            async fn write_private_file(path: &str, contents: &str) -> anyhow::Result<()> {
                let p = Path::new(path);
                if let Some(parent) = p.parent() {
                    if !parent.as_os_str().is_empty() {
                        tokio::fs::create_dir_all(parent).await?;
                    }
                }
                let mut opts = std::fs::OpenOptions::new();
                opts.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600);
                }
                let mut f = opts.open(p)?;
                std::io::Write::write_all(&mut f, contents.as_bytes())?;
                Ok(())
            }

            write_file(&ca, &ca_pem).await?;
            write_file(&cert, &server_chain_pem).await?;
            write_private_file(&key, &server_key_pem).await?;

            crate::pm::daemon::pm_event(
                "web",
                None,
                format!(
                    "web_console tls_autogen complete ca={} cert={} key={} cn={} san_dns={} san_ip={} valid_days={} not_before_days_ago=3",
                    ca,
                    cert,
                    key,
                    common_name,
                    dns_names.join(","),
                    ip_addrs.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(","),
                    AUTOGEN_CERT_VALID_DAYS
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

    let (ca, cert, key) = ensure_tls_material(&cfg, addr).await?;

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
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}



#[cfg(test)]
mod tests {
    use super::*;

    // ---- timing-safe primitives ------------------------------------------------

    #[test]
    fn dummy_bcrypt_hash_is_a_real_verifiable_hash() {
        // This matters more than it looks: if the constant were malformed,
        // bcrypt::verify would return Err *immediately* instead of doing the work,
        // which would silently restore the username-enumeration timing oracle it
        // exists to close.
        let r = bcrypt::verify("any password at all", DUMMY_BCRYPT_HASH);
        assert!(r.is_ok(), "DUMMY_BCRYPT_HASH is not a parseable bcrypt hash");
        assert!(!r.unwrap(), "DUMMY_BCRYPT_HASH must not match a guessable password");
    }

    #[test]
    fn ct_eq_matches_ordinary_equality() {
        assert!(ct_eq("", ""));
        assert!(ct_eq("abc", "abc"));
        assert!(ct_eq(&"x".repeat(64), &"x".repeat(64)));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "ab"));
        assert!(!ct_eq("", "a"));
        // Differences in the final byte must be caught just as reliably as the first.
        assert!(!ct_eq("aaaaaaaaZ", "aaaaaaaaY"));
        assert!(!ct_eq("Zaaaaaaaa", "Yaaaaaaaa"));
    }

    // ---- systemd argument allow-lists ------------------------------------------

    #[test]
    fn systemd_unit_names_reject_injection_and_traversal() {
        for bad in [
            "foo.service; rm -rf /",
            "../../etc/passwd",
            "foo.service && reboot",
            "foo.socket",
            "foo",
            "",
            "$(reboot).service",
            "foo bar.service",
        ] {
            assert!(
                validate_systemd_unit(bad).is_err(),
                "{bad:?} must be rejected as a systemd unit"
            );
        }
    }

    #[test]
    fn systemd_unit_names_accept_ordinary_units() {
        for ok in ["processmaster.service", "nginx.service", "user@1000.service"] {
            assert!(
                validate_systemd_unit(ok).is_ok(),
                "{ok:?} should be a valid systemd unit"
            );
        }
    }

    #[test]
    fn systemd_actions_are_restricted_to_a_known_set() {
        assert!(validate_systemd_action("start").is_ok());
        assert!(validate_systemd_action("stop").is_ok());
        for bad in ["mask", "isolate", "poweroff", "", "start;reboot"] {
            assert!(
                validate_systemd_action(bad).is_err(),
                "{bad:?} must not be an accepted systemd action"
            );
        }
    }

    // ---- htpasswd parsing ------------------------------------------------------

    #[test]
    fn htpasswd_entries_split_on_the_first_colon_only() {
        // bcrypt hashes contain '$' and '/', and the hash itself must survive intact.
        let cfg = WebConsoleConfig {
            enabled: true,
            auth: crate::pm::config::WebConsoleAuthConfig {
                basic: crate::pm::config::WebConsoleBasicAuthConfig {
                    users: vec![format!("alice:{DUMMY_BCRYPT_HASH}")],
                },
            },
            ..Default::default()
        };
        let users = parse_htpasswd_users(&cfg).expect("parses");
        assert_eq!(users.get("alice").map(String::as_str), Some(DUMMY_BCRYPT_HASH));
    }

    #[test]
    fn htpasswd_rejects_entries_without_a_colon() {
        let cfg = WebConsoleConfig {
            enabled: true,
            auth: crate::pm::config::WebConsoleAuthConfig {
                basic: crate::pm::config::WebConsoleBasicAuthConfig {
                    users: vec!["no-colon-here".to_string()],
                },
            },
            ..Default::default()
        };
        assert!(parse_htpasswd_users(&cfg).is_err());
    }

    // ---- cookies ---------------------------------------------------------------

    #[test]
    fn cookie_get_finds_the_named_cookie_among_others() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("other=1; pm_csrf=abc123; trailing=2"),
        );
        assert_eq!(cookie_get(&h, CSRF_COOKIE).as_deref(), Some("abc123"));
        assert_eq!(cookie_get(&h, "nope"), None);
        assert_eq!(cookie_get(&HeaderMap::new(), CSRF_COOKIE), None);
    }

    #[test]
    fn csrf_tokens_are_unpredictable_and_long_enough() {
        let a = new_csrf_token();
        let b = new_csrf_token();
        assert_ne!(a, b, "tokens must not repeat");
        // 32 random bytes, base64url without padding.
        assert!(a.len() >= 40, "token {a:?} is shorter than expected");
    }

    // ---- cleartext exposure of console credentials -----------------------------

    fn refused(tls: bool, bind: &str, allow: bool) -> bool {
        let addr = crate::pm::config::parse_bind_addr(bind, 9001).expect("test bind parses");
        plaintext_remote_refused(tls, &addr, allow)
    }

    #[test]
    fn plaintext_console_is_refused_on_reachable_addresses() {
        // The whole point: the shipped default (0.0.0.0, no TLS) must not serve.
        assert!(refused(false, "0.0.0.0", false));
        assert!(refused(false, "::", false));
        assert!(refused(false, "192.168.1.10", false));
        assert!(refused(false, "fe80::1", false));
    }

    #[test]
    fn plaintext_console_is_allowed_on_loopback_or_with_tls_or_opt_in() {
        // Loopback never leaves the host -- all of 127.0.0.0/8, not just 127.0.0.1.
        assert!(!refused(false, "127.0.0.1", false));
        assert!(!refused(false, "127.0.0.53", false));
        assert!(!refused(false, "::1", false));
        // TLS protects the credentials wherever it is bound.
        assert!(!refused(true, "0.0.0.0", false));
        assert!(!refused(true, "10.0.0.5", false));
        // Explicit operator opt-in.
        assert!(!refused(false, "0.0.0.0", true));
    }

    // ---- password digests (no plaintext at rest in memory) ---------------------

    #[test]
    fn password_digest_is_stable_and_does_not_contain_the_password() {
        let key = [7u8; 32];
        let d = keyed_digest(&key, b"correct horse battery staple");
        assert_eq!(d, keyed_digest(&key, b"correct horse battery staple"));
        assert_ne!(d, keyed_digest(&key, b"correct horse battery stapl"));
        assert_ne!(d, keyed_digest(&key, b""));

        // The reported issue was that a memory dump yielded the literal password, so the
        // stored bytes must share nothing with it in either byte order.
        let pass = b"correct horse battery staple";
        let bytes = d.to_le_bytes();
        assert!(
            !bytes.windows(4).any(|w| pass.windows(4).any(|p| p == w)),
            "digest bytes overlap the plaintext"
        );
        assert_ne!(&bytes[..], &pass[..bytes.len()]);
    }

    #[test]
    fn password_digest_is_keyed_so_it_cannot_be_precomputed() {
        let a = keyed_digest(&[1u8; 32], b"hunter2");
        let b = keyed_digest(&[2u8; 32], b"hunter2");
        assert_ne!(a, b, "the per-process key must change the digest");
        // And the live key must actually be random rather than a fixed constant.
        assert_ne!(*password_digest_key(), [0u8; 32]);
    }

    #[test]
    fn zeroing_a_credential_buffer_leaves_nothing_behind() {
        let mut buf = b"alice:hunter2".to_vec();
        zero_bytes(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }

    // ---- auth cache ------------------------------------------------------------

    #[test]
    fn auth_cache_hits_only_on_the_same_user_hash_and_password() {
        let mut c = AuthCache::new();
        let now = Instant::now();
        let good = password_digest("s3cret");
        c.put_ok("alice".to_string(), "hash-a".to_string(), good, now);

        assert!(c.is_cached_ok("alice", "hash-a", good, now));
        // A wrong password must still reach bcrypt.
        assert!(!c.is_cached_ok("alice", "hash-a", password_digest("s3cre"), now));
        // A rotated htpasswd entry invalidates the cached decision.
        assert!(!c.is_cached_ok("alice", "hash-b", good, now));
        assert!(!c.is_cached_ok("bob", "hash-a", good, now));
    }

    #[test]
    fn auth_cache_entries_expire() {
        let mut c = AuthCache::new();
        let now = Instant::now();
        let d = password_digest("s3cret");
        c.put_ok("alice".to_string(), "hash-a".to_string(), d, now);
        assert!(c.is_cached_ok("alice", "hash-a", d, now + AuthCache::TTL - Duration::from_secs(1)));
        // Past the TTL a credential must be re-verified, so revocation takes effect.
        assert!(!c.is_cached_ok("alice", "hash-a", d, now + AuthCache::TTL));
        assert!(!c.is_cached_ok("alice", "hash-a", d, now + AuthCache::TTL * 2));
    }

    #[test]
    fn auth_cache_is_bounded() {
        let mut c = AuthCache::new();
        let now = Instant::now();
        for i in 0..(AuthCache::MAX_ENTRIES + 50) {
            c.put_ok(format!("user{i}"), "h".to_string(), i as u128, now);
        }
        assert!(c.entries.len() <= AuthCache::MAX_ENTRIES);
    }

    // ---- auth failure logging --------------------------------------------------

    #[test]
    fn auth_failures_are_logged_then_rate_limited_per_source() {
        let mut l = AuthFailureLimiter::new();
        let t0 = Instant::now();

        // The first few attempts are always visible.
        for _ in 0..AUTH_FAIL_BURST {
            assert_eq!(l.note("10.0.0.1", t0), Some(0));
        }
        // A spray after that must not be able to flood the bounded event ring...
        for _ in 0..10_000 {
            assert_eq!(l.note("10.0.0.1", t0), None);
        }
        // ...but the attempts are still accounted for at the next emission.
        assert_eq!(l.note("10.0.0.1", t0 + AUTH_FAIL_QUIET), Some(10_000));
        // Suppression is per source: a different attacker is not hidden by the first.
        assert_eq!(l.note("10.0.0.2", t0), Some(0));
    }

    #[tokio::test]
    async fn a_challenge_is_not_recorded_as_a_failed_login() {
        let users: HashMap<String, String> = HashMap::new();
        let cache = Arc::new(Mutex::new(AuthCache::new()));

        // No credentials: every first page load looks like this, and it is not an attempt.
        let denied = check_basic_auth(&users, &cache, &HeaderMap::new()).await.unwrap_err();
        assert!(!denied.attempted);

        // Credentials that were sent but are unusable are a real, loggable rejection.
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic !!!not-base64!!!"));
        let denied = check_basic_auth(&users, &cache, &h).await.unwrap_err();
        assert!(denied.attempted);
        assert_eq!(denied.known_user, None);
    }

    #[test]
    fn auth_failure_sources_are_bounded() {
        let mut l = AuthFailureLimiter::new();
        let t0 = Instant::now();
        for i in 0..(AUTH_FAIL_MAX_SOURCES + 100) {
            l.note(&format!("10.1.{}.{}", i / 256, i % 256), t0);
        }
        assert!(l.sources.len() <= AUTH_FAIL_MAX_SOURCES);
    }

    // ---- RPC audit trail -------------------------------------------------------

    #[test]
    fn state_changing_rpcs_are_audited() {
        let p = serde_json::json!({ "name": "billing", "unit": "sshd.service", "action": "stop" });
        for m in [
            "start", "stop", "restart", "enable", "disable", "flag", "unflag", "admin_action",
            "start_all", "stop_all", "restart_all", "update", "systemd_action",
            "admin_actions_kill",
        ] {
            assert!(audit_target(m, &p).is_some(), "{m} must be audited");
        }
        assert_eq!(audit_target("stop", &p).as_deref(), Some("target=billing"));
        assert_eq!(
            audit_target("systemd_action", &p).as_deref(),
            Some("unit=sshd.service systemd_action=stop")
        );
    }

    #[test]
    fn read_only_rpcs_are_not_audited() {
        // These are polled by every open browser tab; logging them would evict the
        // audit records this feature exists to keep.
        let p = serde_json::json!({ "name": "billing" });
        for m in [
            "status", "events", "logs", "service_details", "systemd_list", "systemd_logs",
            "systemd_service_details", "admin_actions_pids", "definitely_not_a_method",
        ] {
            assert!(audit_target(m, &p).is_none(), "{m} must not be audited");
        }
    }

    #[test]
    fn audited_parameters_cannot_forge_event_lines() {
        // Everything here is client-supplied and lands in an operator-facing log.
        let injected = sanitize_event_field("billing\nauth_failure ip=1.2.3.4 user=root");
        assert!(!injected.contains('\n'));
        assert!(!injected.contains('\r'));
        assert_eq!(sanitize_event_field("   "), "-");
        assert_eq!(sanitize_event_field(""), "-");
        let long = sanitize_event_field(&"a".repeat(500));
        assert!(long.len() <= 70, "{long:?} was not truncated");
    }

    // ---- auto-generated certificate --------------------------------------------

    #[test]
    fn cert_common_name_names_the_host() {
        assert_eq!(autogen_cert_common_name(Some("build01.example.com")), "build01.example.com");
        // "test" told an operator nothing; the fallback should at least name the product.
        assert_eq!(autogen_cert_common_name(None), "processmaster");
    }

    #[test]
    fn cert_sans_always_cover_loopback() {
        let (dns, ips) = autogen_cert_sans(None, "0.0.0.0".parse().unwrap(), None);
        assert!(dns.contains(&"localhost".to_string()));
        assert!(ips.contains(&IpAddr::from([127, 0, 0, 1])));
        assert!(ips.contains(&IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn cert_sans_include_the_concrete_bind_address_but_not_a_wildcard() {
        let (_, ips) = autogen_cert_sans(None, "10.4.5.6".parse().unwrap(), None);
        assert!(ips.contains(&"10.4.5.6".parse::<IpAddr>().unwrap()));

        // A wildcard bind names no interface, so there is nothing to certify.
        for wildcard in ["0.0.0.0", "::"] {
            let (_, ips) = autogen_cert_sans(None, wildcard.parse().unwrap(), None);
            assert!(!ips.contains(&wildcard.parse::<IpAddr>().unwrap()));
        }
    }

    #[test]
    fn cert_sans_include_the_hostname_and_client_host() {
        let (dns, ips) = autogen_cert_sans(
            Some("Console.Example.COM"),
            "0.0.0.0".parse().unwrap(),
            Some("build01"),
        );
        assert!(dns.contains(&"build01".to_string()));
        // Hostnames are case-insensitive; SANs must be normalized or matching fails.
        assert!(dns.contains(&"console.example.com".to_string()));

        // A client_host that is an IP literal belongs in the IP set: a DNS SAN holding
        // an address never matches.
        let (dns, ips2) = autogen_cert_sans(Some("203.0.113.9"), "0.0.0.0".parse().unwrap(), None);
        assert!(ips2.contains(&"203.0.113.9".parse::<IpAddr>().unwrap()));
        assert!(!dns.contains(&"203.0.113.9".to_string()));
        assert!(!ips.is_empty());
    }

    // ---- certificate expiry detection ------------------------------------------

    fn test_cert_der(not_after: OffsetDateTime, issuer_cn: &str) -> Vec<u8> {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
        let key = KeyPair::generate().expect("keypair");
        let mut p = CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        p.not_before = not_after - TimeDuration::days(30);
        p.not_after = not_after;
        p.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, issuer_cn);
            dn
        };
        // Self-signed, so issuer == subject and the CN below is what we read back.
        p.self_signed(&key).expect("self-signed").der().to_vec()
    }

    #[test]
    fn certificate_expiry_is_read_back_exactly() {
        // Both ASN.1 spellings: certificates use UTCTime before 2050 and
        // GeneralizedTime after, and reading the wrong one misdates the expiry.
        for ts in [2_000_000_000i64 /* 2033, UTCTime */, 2_600_000_000 /* 2052, GeneralizedTime */] {
            let expected = OffsetDateTime::from_unix_timestamp(ts).unwrap();
            let der = test_cert_der(expected, "processmaster-ca");
            let (got, _) = cert_not_after_and_issuer(&der).expect("parses a cert we just made");
            assert_eq!(got, expected, "for unix ts {ts}");
        }
    }

    #[test]
    fn expired_certificates_are_distinguished_from_valid_ones() {
        let now = OffsetDateTime::now_utc();
        let fresh = test_cert_der(now + TimeDuration::days(10), AUTOGEN_CA_COMMON_NAME);
        let (na, _) = cert_not_after_and_issuer(&fresh).unwrap();
        assert!(na > now);

        let stale = test_cert_der(now - TimeDuration::days(1), AUTOGEN_CA_COMMON_NAME);
        let (na, issuer) = cert_not_after_and_issuer(&stale).unwrap();
        assert!(na < now, "an expired cert must not read as still valid");
        // Only our own material may be regenerated in place.
        assert!(issuer
            .windows(AUTOGEN_CA_COMMON_NAME.len())
            .any(|w| w == AUTOGEN_CA_COMMON_NAME.as_bytes()));

        let foreign = test_cert_der(now - TimeDuration::days(1), "corp-issuing-ca");
        let (_, issuer) = cert_not_after_and_issuer(&foreign).unwrap();
        assert!(!issuer
            .windows(AUTOGEN_CA_COMMON_NAME.len())
            .any(|w| w == AUTOGEN_CA_COMMON_NAME.as_bytes()));
    }

    #[test]
    fn malformed_certificates_never_read_as_valid() {
        // The fallback has to be "unknown", so a truncated or junk file can never be
        // mistaken for a live certificate.
        assert!(cert_not_after_and_issuer(&[]).is_none());
        assert!(cert_not_after_and_issuer(b"not a certificate").is_none());
        let der = test_cert_der(OffsetDateTime::now_utc(), "x");
        assert!(cert_not_after_and_issuer(&der[..der.len() / 2]).is_none());
        assert!(cert_not_after_and_issuer(&der[1..]).is_none());
    }

    #[test]
    fn autogen_certificates_are_not_long_lived() {
        // 397 days is the browser-accepted maximum; the 20-year original meant a leaked
        // key stayed useful for the life of the machine.
        assert!(AUTOGEN_CERT_VALID_DAYS <= 397);
    }
}
