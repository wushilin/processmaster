//! The control socket: reading requests and routing them to their handlers.

use super::*;

pub(super) async fn handle_connection_async(
    state: Arc<Mutex<DaemonState>>,
    stream: tokio::net::UnixStream,
) -> anyhow::Result<()> {
    let mut reader = TokioBufReader::new(stream);
    let mut line = String::new();
    // Bound the request line. An unbounded `read_line` lets anything that can open the
    // socket grow this String until the root daemon is OOM-killed, taking supervision
    // of every managed service with it. Real requests are a few hundred bytes.
    const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
    let n = {
        use tokio::io::AsyncReadExt as _;
        let mut limited = (&mut reader).take(MAX_REQUEST_BYTES);
        // And bound it in time: a silent client must not hold a connection forever.
        const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);
        let n = tokio_time::timeout(REQUEST_READ_TIMEOUT, limited.read_line(&mut line))
            .await
            .map_err(|_| anyhow::anyhow!("no request within {REQUEST_READ_TIMEOUT:?}"))??;
        anyhow::ensure!(
            n < MAX_REQUEST_BYTES as usize,
            "request exceeds {MAX_REQUEST_BYTES} byte limit"
        );
        n
    };
    if n == 0 || line.trim().is_empty() {
        return Ok(());
    }
    let wire: crate::pm::rpc::WireRequest = serde_json::from_str(line.trim_end())?;

    // Grab the underlying stream back so we can write response (or hand to follow).
    let mut stream = reader.into_inner();

    let daemon_build_time = option_env!("PROCESSMASTER_BUILD_TIME").unwrap_or("unknown");
    let daemon_build_host = option_env!("PROCESSMASTER_BUILD_HOST").unwrap_or("unknown");
    if wire.client.build_time != daemon_build_time || wire.client.build_host != daemon_build_host {
        let resp = Response::message(false, format!(
                "pmctl is not co-built with this daemon.\n\
daemon: build_time={daemon_build_time} build_host={daemon_build_host}\n\
client: build_time={} build_host={}\n\
\n\
Fix: use the `pmctl` binary built from the same build/release as the running daemon.",
                wire.client.build_time, wire.client.build_host
            ));
        let resp_line = serde_json::to_string(&resp)? + "\n";
        stream.write_all(resp_line.as_bytes()).await?;
        stream.flush().await?;
        return Ok(());
    }

    match wire.request {
        Request::LogsFollow { name, filename, n, .. } => {
            // Long-running follow loop; keep it off the core runtime threads for now.
            // Cap concurrent follow sessions well below the blocking-pool size, so
            // however many clients attach, supervision work always has threads left.
            let permit = match log_follow_semaphore().clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    let resp = Response::message(false, format!(
                            "too many concurrent log-follow sessions (limit {MAX_CONCURRENT_LOG_FOLLOWS}); try again shortly"
                        ));
                    let line = serde_json::to_string(&resp)? + "\n";
                    stream.write_all(line.as_bytes()).await?;
                    stream.flush().await?;
                    return Ok(());
                }
            };
            let std_stream = stream.into_std()?;
            let _ = std_stream.set_nonblocking(false);
            let st = Arc::clone(&state);
            tasks().spawn_blocking(move || {
                // Held for the lifetime of the session; released on any exit path.
                let _permit = permit;
                handle_logs_follow(st, std_stream, name, filename, n)
            })
                .await
                .map_err(|e| anyhow::anyhow!("join error: {e}"))??;
            Ok(())
        }
        other => {
            let resp = match dispatch_async(state, other).await {
                Ok(r) => r,
                Err(e) => Response {
                    ok: false,
                    // Use the full anyhow chain so clients can actually debug failures (e.g. spawn/pre_exec/cgroup issues).
                    message: format!("{e:#}"),
                    ..Default::default()
                },
            };
            let resp_line = serde_json::to_string(&resp)? + "\n";
            stream.write_all(resp_line.as_bytes()).await?;
            stream.flush().await?;
            Ok(())
        }
    }
}

pub(crate) async fn dispatch_async(state: Arc<Mutex<DaemonState>>, req: Request) -> anyhow::Result<Response> {
    // Once shutdown has begun (stop everything, then drain the cgroups), refuse anything
    // that would start processes: the web console can still be serving requests, and a
    // start or admin action landing mid-drain would be spawned and then cut off.
    let spawns = matches!(
        req,
        Request::Update
            | Request::AdminAction { .. }
            | Request::Start { .. }
            | Request::Restart { .. }
            | Request::StartAll { .. }
            | Request::RestartAll { .. }
            | Request::Enable { .. }
    );
    if spawns {
        let shutting_down = state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .shutting_down
            .load(Ordering::Relaxed);
        if shutting_down {
            return Ok(admin_refusal("processmaster is shutting down; refusing to start anything".to_string()));
        }
    }
    match req {
        Request::Update => do_update_async(&state).await,
        Request::AdminAction { name } => do_admin_action_async(&state, &name).await,
        Request::AdminList => do_admin_list(&state),
        Request::AdminKill => do_admin_kill(&state),
        Request::AdminPs => do_admin_ps(&state),
        Request::ServerVersion => do_server_version(),
        Request::PerfMetrics { name } => {
            tasks()
                .spawn_blocking({
                    let st = Arc::clone(&state);
                    move || do_perf_metrics(&st, &name)
                })
                .await
                .map_err(|e| anyhow::anyhow!("join error: {e}"))?
        }
        Request::Start { name, force } => do_start_async(&state, &name, force).await,
        Request::Stop { name } => do_stop_async(&state, &name).await,
        Request::Restart { name, force } => do_restart_async(&state, &name, force).await,
        Request::StartAll { force } => do_start_all_async(&state, force).await,
        Request::StopAll => do_stop_all_async(&state).await,
        Request::RestartAll { force } => do_restart_all_async(&state, force).await,
        Request::Flag { name, flags, ttl } => {
            tasks().spawn_blocking({
                let st = Arc::clone(&state);
                move || do_flag(&st, &name, &flags, ttl.as_deref())
            })
            .await
            .map_err(|e| anyhow::anyhow!("join error: {e}"))?
        }
        Request::Unflag { name, flags } => {
            tasks().spawn_blocking({
                let st = Arc::clone(&state);
                move || do_unflag(&st, &name, &flags)
            })
            .await
            .map_err(|e| anyhow::anyhow!("join error: {e}"))?
        }
        Request::Enable { name } => do_set_enabled_async(&state, &name, true).await,
        Request::Disable { name } => do_set_enabled_async(&state, &name, false).await,
        Request::Logs { name, n } => {
            tasks().spawn_blocking({
                let st = Arc::clone(&state);
                move || do_logs(&st, &name, n)
            })
            .await
            .map_err(|e| anyhow::anyhow!("join error: {e}"))?
        }
        Request::Status { name } => {
            tasks().spawn_blocking({
                let st = Arc::clone(&state);
                move || do_status(&st, name.as_deref())
            })
            .await
            .map_err(|e| anyhow::anyhow!("join error: {e}"))?
        }
        Request::Events { name, n } => {
            tasks().spawn_blocking({
                let st = Arc::clone(&state);
                move || do_events(&st, name.as_deref(), n)
            })
            .await
            .map_err(|e| anyhow::anyhow!("join error: {e}"))?
        }
        _ => Err(anyhow::anyhow!("unsupported request")),
    }
}
