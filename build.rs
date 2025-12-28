use std::env;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn cmd_stdout(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Prefer reproducible builds when SOURCE_DATE_EPOCH is set.
    let build_time = if let Ok(sde) = env::var("SOURCE_DATE_EPOCH") {
        format!("epoch:{sde}")
    } else {
        cmd_stdout("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]).unwrap_or_else(|| {
            let secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            format!("epoch:{secs}")
        })
    };

    let build_host = env::var("HOSTNAME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| cmd_stdout("hostname", &[]))
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=PROCESSMASTER_BUILD_TIME={build_time}");
    println!("cargo:rustc-env=PROCESSMASTER_BUILD_HOST={build_host}");
}



