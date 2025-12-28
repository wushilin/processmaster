use chrono::TimeZone as _;

pub fn build_host() -> &'static str {
    option_env!("PROCESSMASTER_BUILD_HOST").unwrap_or("unknown")
}

pub fn build_time_raw() -> &'static str {
    option_env!("PROCESSMASTER_BUILD_TIME").unwrap_or("unknown")
}

pub fn build_time_pretty() -> String {
    format_build_time_pretty(build_time_raw())
}

pub fn format_build_time_pretty(raw: &str) -> String {
    let raw = raw.trim();
    if let Some(epoch) = raw.strip_prefix("epoch:") {
        if let Ok(secs) = epoch.trim().parse::<i64>() {
            // Render in UTC, stable across environments.
            if let Some(dt) = chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0) {
                return dt.format("%Y-%m-%d %H:%M:%S").to_string();
            }
            return chrono::Utc
                .timestamp_opt(0, 0)
                .unwrap()
                .format("%Y-%m-%d %H:%M:%S")
                .to_string();
        }
    }

    // Common case: RFC3339 "YYYY-MM-DDTHH:MM:SSZ" -> "YYYY-MM-DD HH:MM:SS" (UTC)
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(raw) {
        return dt
            .with_timezone(&chrono::Utc)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
    }

    // Best-effort fallback.
    raw.replace('T', " ").trim_end_matches('Z').to_string()
}

pub fn banner() -> String {
    format!(
        "Process master (built on {} at {}).",
        build_host(),
        build_time_pretty()
    )
}


