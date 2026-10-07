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
    auth: Arc<Authenticator>,
    auth_failures: Arc<Mutex<AuthFailureLimiter>>,
    auth_throttle: Arc<Mutex<AuthThrottle>>,
    // Separate from auth_failures so lockout notices are not swallowed by the failure
    // burst that caused them.
    auth_lockouts: Arc<Mutex<AuthFailureLimiter>>,
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

    let (dummy_cost, cost_warning) = dummy_bcrypt_cost(&users);
    if let Some(w) = cost_warning {
        crate::pm::daemon::pm_event("web", None, format!("web_console warning: {w}"));
    }

    crate::pm::daemon::tasks().spawn(async move {
        // Hashing at a real cost takes up to a second or so; keep it off the async workers.
        let dummy_hash = match tokio::task::spawn_blocking(move || make_dummy_bcrypt_hash(dummy_cost))
            .await
            .map_err(anyhow::Error::from)
            .and_then(|r| r)
        {
            Ok(h) => h,
            Err(e) => {
                crate::pm::daemon::pm_event("web", None, format!("web_console disabled: {e}"));
                return;
            }
        };
        let st = WebState {
            daemon: Arc::clone(&state),
            auth: Arc::new(Authenticator::new(users, dummy_hash, bcrypt_verify_permits())),
            auth_failures: Arc::new(Mutex::new(AuthFailureLimiter::new())),
            auth_throttle: Arc::new(Mutex::new(AuthThrottle::new())),
            auth_lockouts: Arc::new(Mutex::new(AuthFailureLimiter::new())),
            tls_enabled: cfg.tls.enabled,
        };
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
        if let Some(cost) = bcrypt_cost(&normalized) {
            anyhow::ensure!(
                cost <= MAX_SUPPORTED_BCRYPT_COST,
                "bcrypt cost {cost} for user {user:?} exceeds the supported maximum of \
                 {MAX_SUPPORTED_BCRYPT_COST} (each login would take minutes or more, and startup \
                 must hash a dummy at the same cost) -- re-hash with e.g. \
                 `htpasswd -nbB -C 12 {user} password`"
            );
        }
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
    mount_console(inner)
}

/// Mounts the (already authenticated) console routes under `/processmaster` and adds
/// the root-level aliases and the outermost response layers. Split from build_router so
/// the outer wiring can be tested without a daemon.
fn mount_console(inner: Router) -> Router {
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
        // Outermost, so it also covers redirects and the 401/429/503 auth replies.
        .layer(middleware::map_response(security_headers))
}

/// Anti-framing (clickjacking a root console into clicking "run admin action"), no MIME
/// sniffing, and no Referer leaking console URLs to anything linked from the page.
///
/// The CSP is deliberately *only* `frame-ancestors`: the status page relies on inline
/// scripts and styles, so a script-src policy would break it without a nonce scheme.
async fn security_headers(mut resp: AxumResponse) -> AxumResponse {
    let h = resp.headers_mut();
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("frame-ancestors 'none'"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    resp
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

// ---------------- per-source login throttle ----------------

// AuthFailureLimiter only decides what gets *logged*; this decides what gets *tried*.
// Without it every request carrying a Basic header costs a full bcrypt verify, so one
// source could guess passwords as fast as the host has cores. After
// THROTTLE_MAX_FAILURES failures with no THROTTLE_WINDOW-long gap between them, the
// source is refused with 429 -- without running bcrypt -- for THROTTLE_BASE_LOCKOUT.
// Requests made while locked are refused but neither counted nor extend the lockout (an
// admin's open console tab polls every second or two and would otherwise hold its own
// address locked forever). A failure after a lockout has run out locks again for twice
// as long, up to THROTTLE_MAX_LOCKOUT.
//
// A successful login deliberately does *not* clear the record: behind NAT or a reverse
// proxy the admin and an attacker share one source, and a logged-in tab's polling would
// otherwise reset the attacker's count every second. The only reset is decay -- a
// source quiet for THROTTLE_WINDOW is forgotten.
const THROTTLE_MAX_FAILURES: u32 = 10;
const THROTTLE_WINDOW: Duration = Duration::from_secs(5 * 60);
const THROTTLE_BASE_LOCKOUT: Duration = Duration::from_secs(30);
const THROTTLE_MAX_LOCKOUT: Duration = Duration::from_secs(15 * 60);
// Bounded so that a sweep from many addresses cannot exhaust memory.
const THROTTLE_MAX_SOURCES: usize = 4096;

/// Throttle key for a peer. IPv6 is collapsed to its /64: a single host is routinely
/// handed a whole /64, so keying on the full address would let it rotate through 2^64
/// "sources" (and flush every genuine lockout out of the bounded map while doing so).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct ThrottleKey(IpAddr);

impl ThrottleKey {
    fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Self(ip),
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    return Self(IpAddr::V4(v4));
                }
                let s = v6.segments();
                Self(IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0)))
            }
        }
    }
}

struct AuthThrottle {
    sources: HashMap<ThrottleKey, ThrottleState>,
}

struct ThrottleState {
    failures: u32,
    /// Length of the current (or most recent) lockout; zero until the first one.
    backoff: Duration,
    locked_until: Option<Instant>,
    /// The later of the last failure and the end of the last lockout. A source that
    /// stays quiet for THROTTLE_WINDOW past this is forgotten, escalation included.
    quiet_since: Instant,
}

impl ThrottleState {
    fn is_locked(&self, now: Instant) -> bool {
        self.locked_until.is_some_and(|u| now < u)
    }

    fn is_stale(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.quiet_since) >= THROTTLE_WINDOW
    }

    /// Starts a lockout, doubling the previous one. Returns its length.
    fn lock(&mut self, now: Instant) -> Duration {
        self.backoff = if self.backoff.is_zero() {
            THROTTLE_BASE_LOCKOUT
        } else {
            (self.backoff * 2).min(THROTTLE_MAX_LOCKOUT)
        };
        let until = now + self.backoff;
        self.locked_until = Some(until);
        self.quiet_since = until;
        self.backoff
    }
}

impl AuthThrottle {
    fn new() -> Self {
        Self { sources: HashMap::new() }
    }

    /// Consulted before any credential check. Returns how long the source must still
    /// wait if it is locked out. Read-only: a request refused here is not a guess (no
    /// credential was checked), so it neither counts nor extends the lockout.
    fn check(&self, key: ThrottleKey, now: Instant) -> Option<Duration> {
        let until = self.sources.get(&key)?.locked_until.filter(|u| now < *u)?;
        Some(until.saturating_duration_since(now).max(Duration::from_secs(1)))
    }

    /// Records one rejected credential. Returns the lockout length when this failure
    /// starts one (or, after an earlier lockout ran out, starts a longer one).
    fn record_failure(&mut self, key: ThrottleKey, now: Instant) -> Option<Duration> {
        if self.sources.get(&key).is_some_and(|st| st.is_stale(now)) {
            self.sources.remove(&key);
        }
        if !self.sources.contains_key(&key) {
            self.make_room(now);
            self.sources.insert(
                key,
                ThrottleState { failures: 0, backoff: Duration::ZERO, locked_until: None, quiet_since: now },
            );
        }
        let st = self.sources.get_mut(&key)?;
        st.failures = st.failures.saturating_add(1);
        st.quiet_since = st.quiet_since.max(now);
        (st.failures >= THROTTLE_MAX_FAILURES).then(|| st.lock(now))
    }

    fn make_room(&mut self, now: Instant) {
        if self.sources.len() < THROTTLE_MAX_SOURCES {
            return;
        }
        self.sources.retain(|_, st| !st.is_stale(now));
        while self.sources.len() >= THROTTLE_MAX_SOURCES {
            // Evict sources that are not locked out before ones that are, oldest first,
            // so a flood of fresh addresses cannot cheaply lift an active lockout.
            let victim = self
                .sources
                .iter()
                .min_by_key(|(_, st)| (st.is_locked(now), st.quiet_since))
                .map(|(k, _)| *k);
            match victim {
                Some(k) => {
                    self.sources.remove(&k);
                }
                None => break,
            }
        }
    }
}

/// TCP peer of the request, from `ConnectInfo`.
///
/// Deliberately never `X-Forwarded-For` / `X-Real-IP`: those are caller-supplied and
/// would let an attacker attribute their own failures to someone else's address, or
/// evade the per-source throttle by rotating a header. Behind a reverse proxy this is
/// the proxy, so every client behind it shares one throttle record.
fn peer_ip(req: &axum::http::Request<axum::body::Body>) -> Option<IpAddr> {
    req.extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
}

/// Client address for logging; see `peer_ip`.
fn client_ip(req: &axum::http::Request<axum::body::Body>) -> String {
    peer_ip(req)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

async fn basic_auth_middleware(
    State(st): State<WebState>,
    mut req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> AxumResponse {
    let ip = client_ip(&req);
    let key = peer_ip(&req).map(ThrottleKey::from_ip);
    // Only requests carrying credentials are throttled: the bare browser challenge is
    // not a guess, and counting it would lock people out on page loads.
    if req.headers().contains_key(header::AUTHORIZATION) {
        if let Some(key) = key {
            let locked = st
                .auth_throttle
                .lock()
                .ok()
                .and_then(|t| t.check(key, Instant::now()));
            if let Some(wait) = locked {
                note_lockout(&st, &ip, wait);
                return too_many_attempts(wait);
            }
        }
    }

    let headers = req.headers().clone();
    match check_basic_auth(&st.auth, &headers).await {
        Ok(user) => {
            // No throttle reset on success: see the per-source login throttle notes.
            req.extensions_mut().insert(Principal(user));
            next.run(req).await
        }
        Err(denied) if denied.busy => (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, "1")],
            denied.client_message,
        )
            .into_response(),
        Err(denied) => {
            // A request with no Authorization header at all is the ordinary browser
            // challenge handshake, not an attempt at anything -- logging it would bury
            // the real rejections under one line per first page load.
            let emit = if denied.attempted {
                if let Some(key) = key {
                    let locked = st
                        .auth_throttle
                        .lock()
                        .ok()
                        .and_then(|mut t| t.record_failure(key, Instant::now()));
                    if let Some(wait) = locked {
                        note_lockout(&st, &ip, wait);
                    }
                }
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

/// Logs a lockout (rate-limited per source, like auth failures).
fn note_lockout(st: &WebState, ip: &str, wait: Duration) {
    let emit = st
        .auth_lockouts
        .lock()
        .ok()
        .and_then(|mut l| l.note(ip, Instant::now()));
    if let Some(suppressed) = emit {
        crate::pm::daemon::pm_event(
            "web",
            None,
            format!(
                "auth_lockout ip={} retry_after_s={} suppressed_since_last={}",
                ip,
                wait.as_secs(),
                suppressed
            ),
        );
    }
}

fn too_many_attempts(wait: Duration) -> AxumResponse {
    let secs = wait.as_secs().max(1).to_string();
    let mut resp = (StatusCode::TOO_MANY_REQUESTS, "too many failed logins; retry later").into_response();
    if let Ok(v) = HeaderValue::from_str(&secs) {
        resp.headers_mut().insert(header::RETRY_AFTER, v);
    }
    resp
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
    /// Every bcrypt slot was taken, so the credential was never checked. Not a failure.
    busy: bool,
}

impl AuthDenied {
    /// A rejected attempt whose username is not one we know.
    fn anonymous(msg: &str) -> Self {
        Self { client_message: msg.to_string(), known_user: None, attempted: true, busy: false }
    }
    fn for_user(user: &str, msg: &str) -> Self {
        Self { client_message: msg.to_string(), known_user: Some(user.to_string()), attempted: true, busy: false }
    }
    /// No Authorization header: the client is being challenged, not refused.
    fn unchallenged(msg: &str) -> Self {
        Self { client_message: msg.to_string(), known_user: None, attempted: false, busy: false }
    }
    fn busy() -> Self {
        Self { client_message: "server busy, retry shortly".to_string(), known_user: None, attempted: true, busy: true }
    }
}

/// Credential store plus the resources needed to check against it. Kept apart from
/// WebState so it can be exercised without a daemon.
struct Authenticator {
    users: HashMap<String, String>, // username -> bcrypt hash
    /// Verified against when the username is unknown, so that unknown and known users
    /// cost the same wall-clock time (otherwise the response time enumerates valid
    /// usernames). Generated at startup at the configured cost; see dummy_bcrypt_cost.
    dummy_hash: String,
    cache: Mutex<AuthCache>,
    /// Caps concurrent bcrypt verifies. Callers never queue for a slot: a flood of
    /// logins would otherwise pile up on the blocking pool and starve the supervisor.
    bcrypt_slots: Arc<tokio::sync::Semaphore>,
}

impl Authenticator {
    fn new(users: HashMap<String, String>, dummy_hash: String, permits: usize) -> Self {
        Self {
            users,
            dummy_hash,
            cache: Mutex::new(AuthCache::new()),
            bcrypt_slots: Arc::new(tokio::sync::Semaphore::new(permits)),
        }
    }
}

/// Concurrent bcrypt verifies allowed: enough to keep every core busy with logins
/// without letting them monopolise the blocking pool.
fn bcrypt_verify_permits() -> usize {
    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    (2 * cpus).max(2)
}

/// Highest bcrypt cost accepted for a configured user. Each step doubles the work: cost
/// 16 is already seconds per verify, while cost 31 is days -- and startup hashes a dummy
/// at the configured cost, so an unbounded cost would hang console startup (and daemon
/// shutdown, which waits for it). Higher costs are rejected by parse_htpasswd_users.
const MAX_SUPPORTED_BCRYPT_COST: u32 = 16;

/// Parses the cost out of a `$2?$NN$...` bcrypt hash.
fn bcrypt_cost(hash: &str) -> Option<u32> {
    let mut parts = hash.strip_prefix('$')?.splitn(3, '$');
    if !matches!(parts.next()?, "2a" | "2b" | "2x" | "2y") {
        return None;
    }
    let cost: u32 = parts.next()?.parse().ok()?;
    (4..=31).contains(&cost).then_some(cost)
}

/// Picks the cost for the unknown-user dummy hash: the most common configured cost
/// (ties go to the higher, conservative one), so a made-up username takes as long as a
/// typical real one. Also returns a warning for configurations that weaken this.
fn dummy_bcrypt_cost(users: &HashMap<String, String>) -> (u32, Option<String>) {
    let mut counts: std::collections::BTreeMap<u32, usize> = std::collections::BTreeMap::new();
    let mut unparseable = 0usize;
    for hash in users.values() {
        match bcrypt_cost(hash) {
            Some(c) => *counts.entry(c).or_default() += 1,
            None => unparseable += 1,
        }
    }
    let cost = counts
        .iter()
        .max_by_key(|(c, n)| (**n, **c))
        .map(|(c, _)| *c)
        .unwrap_or(bcrypt::DEFAULT_COST)
        // parse_htpasswd_users already rejects higher costs; never hash for days regardless.
        .min(MAX_SUPPORTED_BCRYPT_COST);

    let costs: Vec<String> = counts.keys().map(|c| c.to_string()).collect();
    let mut warnings = Vec::new();
    if counts.len() > 1 {
        warnings.push(format!(
            "basic auth users have mixed bcrypt costs ({}); login response time reveals which \
             usernames exist -- re-hash all users at one cost",
            costs.join(",")
        ));
    }
    if counts.keys().any(|c| *c < 10) {
        warnings.push(format!(
            "basic auth users include bcrypt cost < 10 ({}); such hashes are cheap to brute-force \
             -- re-hash with e.g. `htpasswd -nbB -C 12 user password`",
            costs.join(",")
        ));
    }
    if unparseable > 0 {
        warnings.push(format!(
            "{unparseable} basic auth user(s) have a hash that is not bcrypt ($2a$/$2b$/$2y$); \
             they can never log in"
        ));
    }
    (cost, (!warnings.is_empty()).then(|| warnings.join("; ")))
}

/// bcrypt hash of a random throwaway password, at `cost`.
fn make_dummy_bcrypt_hash(cost: u32) -> anyhow::Result<String> {
    let mut pw = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut pw);
    let pw: String = pw.iter().map(|b| format!("{b:02x}")).collect();
    bcrypt::hash(pw, cost).map_err(|e| anyhow::anyhow!("failed to generate dummy bcrypt hash: {e}"))
}

/// Returns the authenticated username on success.
async fn check_basic_auth(auth: &Authenticator, headers: &axum::http::HeaderMap) -> Result<String, AuthDenied> {
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
    let out = check_decoded_basic_auth(auth, &decoded).await;
    zero_bytes(&mut decoded);
    out
}

async fn check_decoded_basic_auth(auth: &Authenticator, decoded: &[u8]) -> Result<String, AuthDenied> {
    let Ok(s) = std::str::from_utf8(decoded) else {
        return Err(AuthDenied::anonymous("invalid utf8 in Authorization"));
    };
    let Some((user, pass)) = s.split_once(':') else {
        return Err(AuthDenied::anonymous("invalid basic auth payload"));
    };
    let Some(expected_hash) = auth.users.get(user).cloned() else {
        // Unknown user: burn an equivalent bcrypt verify so the reply time does not
        // reveal whether the username exists, then fail with the same message.
        return match bcrypt_verify_blocking(&auth.bcrypt_slots, pass, &auth.dummy_hash).await {
            None => Err(AuthDenied::busy()),
            Some(_) => Err(AuthDenied::anonymous("invalid credentials")),
        };
    };

    // Cache lookup: if this (user, hash, password digest) succeeded before, accept
    // immediately and skip bcrypt (and so needs no bcrypt slot).
    let digest = password_digest(pass);
    if let Ok(mut c) = auth.cache.lock() {
        if c.is_cached_ok(user, &expected_hash, digest, Instant::now()) {
            return Ok(user.to_string());
        }
    }

    // Cache miss: verify once.
    match bcrypt_verify_blocking(&auth.bcrypt_slots, pass, &expected_hash).await {
        None => return Err(AuthDenied::busy()),
        Some(false) => return Err(AuthDenied::for_user(user, "invalid credentials")),
        Some(true) => {}
    }
    // Successful verify: remember it (best-effort).
    if let Ok(mut c) = auth.cache.lock() {
        c.put_ok(user.to_string(), expected_hash, digest, Instant::now());
    }
    Ok(user.to_string())
}

// bcrypt is deliberately CPU-expensive and this daemon shares ONE tokio runtime with
// all supervision work, so a burst of logins on the async workers would starve it.
// Always verify on the blocking pool. Any error (bad hash, join failure) is a mismatch.
//
// Returns None, without verifying, when all bcrypt slots are taken. The permit moves
// into the blocking task so it is held until bcrypt actually finishes, even if the
// client hangs up and this future is dropped first.
async fn bcrypt_verify_blocking(slots: &Arc<tokio::sync::Semaphore>, pass: &str, hash: &str) -> Option<bool> {
    let permit = Arc::clone(slots).try_acquire_owned().ok()?;
    let pass = pass.to_string();
    let hash = hash.to_string();
    Some(matches!(
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            bcrypt::verify(&pass, &hash)
        })
        .await,
        Ok(Ok(true))
    ))
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
    asset_ver: &'static str,
}

/// Content hash of the embedded app.css, appended to its URL as `?v=`. Static assets
/// are cached for a day, so without this a browser keeps the old stylesheet after an
/// upgrade while rendering the new markup.
fn asset_ver() -> &'static str {
    static VER: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VER.get_or_init(|| {
        // FNV-1a: stable across builds and platforms, unlike DefaultHasher.
        let mut h: u64 = 0xcbf29ce484222325;
        for b in APP_CSS {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        format!("{:016x}", h)
    })
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
        asset_ver: asset_ver(),
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
            // Grouped by action id: "<id>: <pid>" per running process.
            let v = match crate::pm::daemon::admin_action_pids_by_id(&cfg) {
                Ok(running) => {
                    let pids: Vec<String> = running
                        .into_iter()
                        .flat_map(|(id, pids)| pids.into_iter().map(move |p| format!("{id}: {p}")))
                        .collect();
                    serde_json::json!({ "ok": true, "message": "", "pids": pids })
                }
                Err(e) => serde_json::json!({ "ok": false, "message": e.to_string(), "pids": [] }),
            };
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
    // Same rules as service definitions: rules out '/', '.', '..' and leading dots, while
    // still allowing names such as `db..backup` that a config can legitimately define.
    crate::pm::app::validate_application_name(app)?;
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
    // A leading '-' would be parsed by root's systemctl as an option (`-H user@host`
    // opens SSH with root's keys). Callers also pass "--"; this is the belt.
    anyhow::ensure!(!t.starts_with('-'), "invalid unit name (leading '-'): {t:?}");
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
    cmd.arg("--no-pager").arg(action).arg("--").arg(unit);
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
        .arg("--no-pager")
        .arg("--property=ControlGroup")
        .arg("--")
        .arg(unit);
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

/// Reads the `flags` param (comma-separated string or array), normalised to lowercase.
///
/// Flags end up in the daemon's state and event log, so anything outside the charset
/// the daemon accepts is refused here too, with a clearer error than the round trip.
fn parse_flags_param(v: Option<&serde_json::Value>) -> Result<Vec<String>, String> {
    let raw: Vec<&str> = match v {
        Some(serde_json::Value::String(s)) => s.split(',').collect(),
        Some(serde_json::Value::Array(a)) => a.iter().filter_map(|v| v.as_str()).collect(),
        _ => vec![],
    };
    let flags: Vec<String> = raw
        .into_iter()
        .map(|x| x.trim().to_ascii_lowercase())
        .filter(|x| !x.is_empty())
        .collect();
    if flags.is_empty() {
        return Err("missing/empty param: flags".to_string());
    }
    if let Some(bad) = flags
        .iter()
        .find(|f| !f.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b':' | b'-')))
    {
        return Err(format!(
            "invalid flag {:?}: only a-z, 0-9, '_', '.', ':' and '-' are allowed",
            sanitize_event_field(bad)
        ));
    }
    Ok(flags)
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
            let flags = parse_flags_param(obj.get("flags"))?;
            let ttl = get_s("ttl");
            Ok(Request::Flag { name, flags, ttl })
        }
        "unflag" => {
            let name = get_s("name").ok_or_else(|| "missing param: name".to_string())?;
            let flags = parse_flags_param(obj.get("flags"))?;
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
    // Same shutdown trigger as the plain-HTTP path; stragglers get a bounded grace
    // period so an open keep-alive connection cannot hold the daemon's exit hostage.
    let handle = axum_server::Handle::new();
    let watcher = {
        let handle = handle.clone();
        tokio::spawn(async move {
            while !shutting_down.load(Ordering::Relaxed) {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            handle.graceful_shutdown(Some(Duration::from_secs(5)));
        })
    };
    let served = axum_server::bind_rustls(addr, tls_config)
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await;
    watcher.abort();
    served?;
    Ok(())
}



#[cfg(test)]
mod tests {
    use super::*;

    // ---- timing-safe primitives ------------------------------------------------

    // A real bcrypt hash (cost 12) of a throwaway password, for parsing tests.
    const SAMPLE_BCRYPT_HASH: &str = "$2b$12$BZCGuMAbOe5rXqoieAs5aOxvCRLsq5VaFUSiKk/7xlEM305d63GN6";

    #[test]
    fn dummy_bcrypt_hash_is_a_real_verifiable_hash() {
        // This matters more than it looks: if the dummy were malformed, bcrypt::verify
        // would return Err *immediately* instead of doing the work, which would
        // silently restore the username-enumeration timing oracle it exists to close.
        let h = make_dummy_bcrypt_hash(4).expect("generates");
        assert_eq!(bcrypt_cost(&h), Some(4), "dummy hash must be at the requested cost");
        for guess in ["any password at all", "", "password", "admin"] {
            let r = bcrypt::verify(guess, &h);
            assert!(r.is_ok(), "dummy hash is not a parseable bcrypt hash");
            assert!(!r.unwrap(), "dummy hash must not match a guessable password");
        }
        // Random per process, so it is not a constant anyone can look up.
        assert_ne!(h, make_dummy_bcrypt_hash(4).unwrap());
    }

    fn users_with_costs(costs: &[&str]) -> HashMap<String, String> {
        costs
            .iter()
            .enumerate()
            .map(|(i, c)| (format!("u{i}"), format!("$2b${c}$BZCGuMAbOe5rXqoieAs5aOxvCRLsq5VaFUSiKk/7xlEM305d63GN6")))
            .collect()
    }

    #[test]
    fn dummy_cost_follows_the_most_common_configured_cost() {
        assert_eq!(dummy_bcrypt_cost(&users_with_costs(&["12"])), (12, None));
        assert_eq!(dummy_bcrypt_cost(&users_with_costs(&["11", "11", "12"])).0, 11);
        // A tie goes to the higher, more expensive cost.
        assert_eq!(dummy_bcrypt_cost(&users_with_costs(&["10", "12"])).0, 12);
        // Nothing parseable: fall back to the library default.
        assert_eq!(dummy_bcrypt_cost(&users_with_costs(&[])).0, bcrypt::DEFAULT_COST);
        assert_eq!(bcrypt_cost("$2y$05$abc"), Some(5));
        assert_eq!(bcrypt_cost("{SHA}abc"), None);
        assert_eq!(bcrypt_cost("$2b$99$abc"), None);
    }

    #[test]
    fn mixed_or_low_bcrypt_costs_are_warned_about() {
        let (_, w) = dummy_bcrypt_cost(&users_with_costs(&["10", "12"]));
        assert!(w.expect("mixed costs warn").contains("mixed"));
        let (cost, w) = dummy_bcrypt_cost(&users_with_costs(&["05"]));
        assert_eq!(cost, 5);
        assert!(w.expect("low cost warns").contains("cost < 10"));
        let mut users = users_with_costs(&["12"]);
        users.insert("md5".to_string(), "$apr1$xyz$abc".to_string());
        assert!(dummy_bcrypt_cost(&users).1.expect("non-bcrypt warns").contains("not bcrypt"));
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
                    users: vec![format!("alice:{SAMPLE_BCRYPT_HASH}")],
                },
            },
            ..Default::default()
        };
        let users = parse_htpasswd_users(&cfg).expect("parses");
        assert_eq!(users.get("alice").map(String::as_str), Some(SAMPLE_BCRYPT_HASH));
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

    #[test]
    fn htpasswd_rejects_bcrypt_costs_above_the_supported_maximum() {
        let cfg_for = |cost: u32| WebConsoleConfig {
            enabled: true,
            auth: crate::pm::config::WebConsoleAuthConfig {
                basic: crate::pm::config::WebConsoleBasicAuthConfig {
                    users: vec![format!("alice:$2y${cost:02}$BZCGuMAbOe5rXqoieAs5aOxvCRLsq5VaFUSiKk/7xlEM305d63GN6")],
                },
            },
            ..Default::default()
        };
        assert!(parse_htpasswd_users(&cfg_for(MAX_SUPPORTED_BCRYPT_COST)).is_ok());
        for cost in [MAX_SUPPORTED_BCRYPT_COST + 1, 31] {
            let err = parse_htpasswd_users(&cfg_for(cost)).expect_err("too costly").to_string();
            assert!(err.contains("exceeds the supported maximum"), "{err}");
        }
        // The dummy never exceeds the cap even if handed such a user directly.
        assert_eq!(dummy_bcrypt_cost(&users_with_costs(&["31"])).0, MAX_SUPPORTED_BCRYPT_COST);
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
        let auth = Authenticator::new(HashMap::new(), make_dummy_bcrypt_hash(4).unwrap(), 2);

        // No credentials: every first page load looks like this, and it is not an attempt.
        let denied = check_basic_auth(&auth, &HeaderMap::new()).await.unwrap_err();
        assert!(!denied.attempted);

        // Credentials that were sent but are unusable are a real, loggable rejection.
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic !!!not-base64!!!"));
        let denied = check_basic_auth(&auth, &h).await.unwrap_err();
        assert!(denied.attempted);
        assert_eq!(denied.known_user, None);
    }

    fn basic_header(user: &str, pass: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        let v = format!("Basic {}", BASE64.encode(format!("{user}:{pass}")));
        h.insert(header::AUTHORIZATION, HeaderValue::from_str(&v).unwrap());
        h
    }

    #[tokio::test]
    async fn saturated_bcrypt_slots_answer_busy_but_cache_hits_still_pass() {
        let hash = bcrypt::hash("s3cret", 4).unwrap();
        let users = HashMap::from([("alice".to_string(), hash)]);
        let auth = Authenticator::new(users, make_dummy_bcrypt_hash(4).unwrap(), 1);

        // Log in once so the credential is cached.
        assert_eq!(check_basic_auth(&auth, &basic_header("alice", "s3cret")).await.ok().as_deref(), Some("alice"));

        // Take the only slot, as a concurrent verify would.
        let held = Arc::clone(&auth.bcrypt_slots).try_acquire_owned().unwrap();
        for (user, pass) in [("alice", "wrong"), ("mallory", "whatever")] {
            let denied = check_basic_auth(&auth, &basic_header(user, pass)).await.unwrap_err();
            assert!(denied.busy, "{user}: a cache miss must not queue behind a full pool");
        }
        // A cached success needs no slot.
        assert_eq!(check_basic_auth(&auth, &basic_header("alice", "s3cret")).await.ok().as_deref(), Some("alice"));

        drop(held);
        let denied = check_basic_auth(&auth, &basic_header("alice", "wrong")).await.unwrap_err();
        assert!(!denied.busy);
        assert_eq!(denied.known_user.as_deref(), Some("alice"));
        // The permit is returned once the verify is done.
        assert_eq!(auth.bcrypt_slots.available_permits(), 1);
    }

    #[test]
    fn bcrypt_permits_are_at_least_two() {
        assert!(bcrypt_verify_permits() >= 2);
    }

    // ---- per-source login throttle ---------------------------------------------

    fn key(s: &str) -> ThrottleKey {
        ThrottleKey::from_ip(s.parse().unwrap())
    }

    #[test]
    fn a_source_is_locked_out_after_repeated_failures() {
        let mut t = AuthThrottle::new();
        let k = key("192.0.2.1");
        let t0 = Instant::now();
        for i in 1..THROTTLE_MAX_FAILURES {
            assert_eq!(t.record_failure(k, t0), None, "failure {i} must not lock yet");
            assert_eq!(t.check(k, t0), None);
        }
        assert_eq!(t.record_failure(k, t0), Some(THROTTLE_BASE_LOCKOUT));
        // Other sources are unaffected.
        assert_eq!(t.check(key("192.0.2.2"), t0), None);
        // Once the lockout runs out the source may try again...
        let after = t0 + THROTTLE_BASE_LOCKOUT;
        assert_eq!(t.check(k, after), None);
        // ...but its next failure locks it again, for twice as long.
        assert_eq!(t.record_failure(k, after), Some(THROTTLE_BASE_LOCKOUT * 2));
    }

    #[test]
    fn lockouts_double_only_on_failures_after_expiry_and_are_capped() {
        let mut t = AuthThrottle::new();
        let k = key("192.0.2.1");
        let mut now = Instant::now();
        for _ in 0..THROTTLE_MAX_FAILURES {
            t.record_failure(k, now);
        }
        let mut expect = THROTTLE_BASE_LOCKOUT;
        for _ in 0..10 {
            // Attempts while locked do not escalate...
            assert_eq!(t.check(k, now), Some(expect));
            assert_eq!(t.check(k, now), Some(expect));
            // ...only a failure once the lockout has run out does.
            now += expect;
            assert_eq!(t.check(k, now), None);
            expect = (expect * 2).min(THROTTLE_MAX_LOCKOUT);
            assert_eq!(t.record_failure(k, now), Some(expect));
        }
        assert_eq!(expect, THROTTLE_MAX_LOCKOUT);
        // Still locked just before the (capped) lockout ends.
        assert!(t.check(k, now + THROTTLE_MAX_LOCKOUT - Duration::from_secs(1)).is_some());
    }

    #[test]
    fn polling_during_a_lockout_does_not_extend_it() {
        // An admin's console tab keeps polling (with credentials) while its address is
        // locked; that must not hold the lockout open forever.
        let mut t = AuthThrottle::new();
        let k = key("192.0.2.1");
        let t0 = Instant::now();
        for _ in 0..THROTTLE_MAX_FAILURES {
            t.record_failure(k, t0);
        }
        let failures = t.sources.get(&k).unwrap().failures;
        for s in 0..THROTTLE_BASE_LOCKOUT.as_secs() {
            let now = t0 + Duration::from_secs(s);
            assert_eq!(t.check(k, now), Some(THROTTLE_BASE_LOCKOUT - Duration::from_secs(s)));
        }
        // Sub-second remainders round up rather than telling the client to retry now.
        let almost = t0 + THROTTLE_BASE_LOCKOUT - Duration::from_millis(10);
        assert_eq!(t.check(k, almost), Some(Duration::from_secs(1)));
        assert_eq!(t.check(k, t0 + THROTTLE_BASE_LOCKOUT), None, "lockout ends on time");
        let st = t.sources.get(&k).unwrap();
        assert_eq!(st.failures, failures, "refused requests are not counted");
        assert_eq!(st.backoff, THROTTLE_BASE_LOCKOUT);
    }

    #[test]
    fn failures_only_reset_by_decay_not_by_success() {
        // There is no success path into the throttle: a logged-in admin behind the same
        // NAT/proxy must not keep wiping an attacker's count. Only quiet time resets it.
        let mut t = AuthThrottle::new();
        let k = key("192.0.2.1");
        let t0 = Instant::now();
        for i in 0..(THROTTLE_MAX_FAILURES - 1) {
            t.record_failure(k, t0 + Duration::from_secs(u64::from(i)));
        }
        let last = t0 + Duration::from_secs(u64::from(THROTTLE_MAX_FAILURES - 2));
        let just_before = last + THROTTLE_WINDOW - Duration::from_secs(1);
        assert_eq!(t.record_failure(k, just_before), Some(THROTTLE_BASE_LOCKOUT));
    }

    #[test]
    fn a_quiet_source_is_forgotten() {
        let mut t = AuthThrottle::new();
        let k = key("192.0.2.1");
        let t0 = Instant::now();
        for _ in 0..(THROTTLE_MAX_FAILURES - 1) {
            t.record_failure(k, t0);
        }
        assert_eq!(t.record_failure(k, t0 + THROTTLE_WINDOW), None);
        assert_eq!(t.sources.get(&k).unwrap().failures, 1);
    }

    #[test]
    fn throttle_sources_are_bounded_and_keep_active_lockouts() {
        let mut t = AuthThrottle::new();
        let t0 = Instant::now();
        let locked = key("198.51.100.7");
        for _ in 0..THROTTLE_MAX_FAILURES {
            t.record_failure(locked, t0);
        }
        for i in 0..(THROTTLE_MAX_SOURCES + 500) {
            t.record_failure(key(&format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256)), t0);
        }
        assert!(t.sources.len() <= THROTTLE_MAX_SOURCES);
        assert!(t.check(locked, t0).is_some(), "a flood of new sources must not lift a lockout");
    }

    #[test]
    fn eviction_still_makes_room_when_every_source_is_locked() {
        let mut t = AuthThrottle::new();
        let t0 = Instant::now();
        let src = |i: usize| key(&format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256));
        for i in 0..THROTTLE_MAX_SOURCES {
            for _ in 0..THROTTLE_MAX_FAILURES {
                t.record_failure(src(i), t0 + Duration::from_millis(i as u64));
            }
        }
        assert_eq!(t.sources.len(), THROTTLE_MAX_SOURCES);
        assert!(t.sources.values().all(|st| st.is_locked(t0 + Duration::from_secs(5))));
        // A new source still gets a record; the oldest locked one is the victim.
        let now = t0 + Duration::from_secs(5);
        assert_eq!(t.record_failure(key("192.0.2.99"), now), None);
        assert_eq!(t.sources.len(), THROTTLE_MAX_SOURCES);
        assert!(t.sources.contains_key(&key("192.0.2.99")));
        assert!(!t.sources.contains_key(&src(0)), "oldest lockout is evicted first");
        assert!(t.check(src(THROTTLE_MAX_SOURCES - 1), now).is_some());
    }

    #[test]
    fn ipv6_sources_are_throttled_per_64() {
        assert_eq!(key("2001:db8:1:2:aaaa::1"), key("2001:db8:1:2:bbbb::2"));
        assert_ne!(key("2001:db8:1:2::1"), key("2001:db8:1:3::1"));
        assert_eq!(key("::ffff:192.0.2.1"), key("192.0.2.1"));
    }

    // ---- misc hardening --------------------------------------------------------

    #[tokio::test]
    async fn responses_carry_anti_framing_and_nosniff_headers() {
        let resp = security_headers((StatusCode::OK, "x").into_response()).await;
        let h = resp.headers();
        assert_eq!(h.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
        assert_eq!(h.get(header::CONTENT_SECURITY_POLICY).unwrap(), "frame-ancestors 'none'");
        assert_eq!(h.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(), "nosniff");
        assert_eq!(h.get(header::REFERRER_POLICY).unwrap(), "no-referrer");
    }

    #[test]
    fn service_cgroup_dir_follows_the_service_name_rules() {
        let cfg = crate::pm::config::MasterConfig::default();
        for bad in ["a/b", "/a", "a/", "..", ".", ".hidden", "", "a b"] {
            assert!(service_cgroup_dir(&cfg, bad).is_err(), "{bad:?} must be rejected");
        }
        for good in ["web-1.api", "db..backup", "a..b"] {
            let dir = service_cgroup_dir(&cfg, good).expect("valid service name");
            assert_eq!(dir.file_name().unwrap(), format!("pm-{good}").as_str());
        }
    }

    #[tokio::test]
    async fn security_headers_are_wired_on_routed_responses_including_401() {
        use tower::ServiceExt;
        // Same outer wiring as build_router; the inner router stands in for the
        // authenticated routes, answering 401 as basic_auth_middleware does.
        let inner = Router::new().route("/status", get(|| async { StatusCode::UNAUTHORIZED }));
        let app = mount_console(inner);
        for (path, status) in [
            ("/processmaster/status", StatusCode::UNAUTHORIZED),
            ("/", StatusCode::TEMPORARY_REDIRECT),
            ("/no-such-route", StatusCode::NOT_FOUND),
        ] {
            let req = axum::http::Request::builder().uri(path).body(axum::body::Body::empty()).unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), status, "{path}");
            let h = resp.headers();
            assert_eq!(h.get(header::X_FRAME_OPTIONS).unwrap(), "DENY", "{path}");
            assert_eq!(h.get(header::CONTENT_SECURITY_POLICY).unwrap(), "frame-ancestors 'none'");
            assert_eq!(h.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(), "nosniff");
            assert_eq!(h.get(header::REFERRER_POLICY).unwrap(), "no-referrer");
        }
    }

    #[test]
    fn flag_params_are_limited_to_the_daemon_charset() {
        let ok = parse_flags_param(Some(&serde_json::json!("Maint, drain:v2"))).unwrap();
        assert_eq!(ok, vec!["maint", "drain:v2"]);
        for bad in [serde_json::json!("a b"), serde_json::json!(["ok", "x\ny"]), serde_json::json!("é")] {
            assert!(parse_flags_param(Some(&bad)).is_err(), "{bad} must be rejected");
        }
        assert!(parse_flags_param(None).is_err());
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
