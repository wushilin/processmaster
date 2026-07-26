//! The configs we ship must actually load.
//!
//! `examples/` and the README are what operators copy from, so a documented key that
//! the parser rejects is a real outage: master and service configs are both
//! `deny_unknown_fields`, so one stale key means the daemon refuses to start.
//!
//! These tests deliberately go through the same public entry points the daemon uses
//! rather than re-implementing parsing.

use std::path::{Path, PathBuf};

use processmaster::pm::app::parse_app_definition_yaml;
use processmaster::pm::config::load_master_config;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn yaml_files_in(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = rd
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"))
        })
        .collect();
    out.sort();
    out
}

#[test]
fn every_example_master_config_loads() {
    let examples = repo_root().join("examples");
    // These are master configs; service definitions live in examples/config.d.
    let masters = ["config.yaml", "config.full.yaml"];

    for name in masters {
        let path = examples.join(name);
        assert!(path.is_file(), "missing shipped example {}", path.display());
        let cfg = load_master_config(&path)
            .unwrap_or_else(|e| panic!("shipped example {} failed to load: {e:#}", path.display()));

        // A config that loads but points nowhere would still be useless.
        assert!(
            !cfg.cgroup_root.trim().is_empty(),
            "{name}: cgroup.root must not be empty"
        );
        assert!(
            !cfg.cgroup_name.trim().is_empty(),
            "{name}: cgroup.name must not be empty"
        );
    }
}

#[test]
fn the_repo_root_config_loads() {
    // config.yaml at the repo root is the default the daemon picks up with no -c flag.
    let path = repo_root().join("config.yaml");
    if !path.is_file() {
        return;
    }
    load_master_config(&path)
        .unwrap_or_else(|e| panic!("repo-root config.yaml failed to load: {e:#}"));
}

#[test]
fn every_example_service_definition_loads() {
    let mut checked = 0usize;
    for dir in [
        repo_root().join("examples"),
        repo_root().join("examples").join("config.d"),
    ] {
        for path in yaml_files_in(&dir) {
            // Master configs live alongside the service samples; skip them here.
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if name.starts_with("config") {
                continue;
            }
            let raw = std::fs::read_to_string(&path).expect("read example");
            let def = parse_app_definition_yaml(&raw, &path, None)
                .unwrap_or_else(|e| panic!("{} failed to load: {e:#}", path.display()));
            assert!(
                !def.application.trim().is_empty(),
                "{} produced an empty service name",
                path.display()
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "no example service definitions were found to check");
}

#[test]
fn example_socket_mode_is_not_world_writable() {
    // Regression guard for the octal-mode bug: `mode: 660` used to be read as decimal
    // 660 (0o1224), and `mode: 750` as 0o1356 — which grants "other" write access and
    // therefore lets any local user connect to the root RPC socket.
    for name in ["config.yaml", "config.full.yaml"] {
        let path = repo_root().join("examples").join(name);
        if !path.is_file() {
            continue;
        }
        let cfg = load_master_config(&path).expect("example loads");
        assert_eq!(
            cfg.sock_mode & 0o002,
            0,
            "{name}: socket mode 0o{:o} grants world write, which permits connect(2)",
            cfg.sock_mode
        );
        assert!(
            cfg.sock_mode <= 0o777,
            "{name}: socket mode 0o{:o} has unexpected high bits",
            cfg.sock_mode
        );
    }
}
