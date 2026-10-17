//! System and user flags on a service: the flag model, the rules that tie system flags
//! together, TTL parsing, and the background expiry of timed flags.

use super::*;

pub(super) const EMBEDDED_FLAG_RULES_JSON: &str = include_str!("../flag_rules.default.json");

#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct FlagRuleFileEntry {
    #[serde(default)]
    clears: Vec<String>,
    #[serde(default)]
    also_sets: Vec<String>,
}

pub(super) type FlagRulesFile = HashMap<String, FlagRuleFileEntry>;

#[derive(Debug, Clone, Default)]
pub(super) struct FlagRuleCompiled {
    clear_all_except_fresh: bool,
    clears: Vec<SystemFlag>,
    also_sets: Vec<SystemFlag>,
}

pub(super) type FlagRulesCompiled = HashMap<SystemFlag, FlagRuleCompiled>;

pub(super) const MAX_USER_FLAG_LEN: usize = 50;
pub(super) const MAX_USER_FLAGS_PER_APP: usize = 100;
pub(super) static FLAG_RULES: OnceLock<FlagRulesCompiled> = OnceLock::new();

// Operator intent is expressed via transient system flags (not persisted).
pub(super) const SYSFLAG_USER_STOP: SystemFlag = SystemFlag::UserStop;
pub(super) const SYSFLAG_USER_START: SystemFlag = SystemFlag::UserStart;
pub(super) const SYSFLAG_OT_KILLED: SystemFlag = SystemFlag::OtKilled;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum SystemFlag {
    Failed,
    Backoff,
    Outdated,
    UserStop,
    UserStart,
    OtKilled,
    ExitOk,
    ExitErr,
    Dummy1,
    Dummy2,
    Dummy3,
    Dummy4,
    Dummy5,
    Dummy6,
    Dummy7,
    Dummy8,
    Dummy9,
    Dummy10,
    SystemStart,
    NoFlag,
    #[allow(dead_code)] // constructed by the flag rules engine (runtime-configured)
    FlagBug,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // may be extended with RUNNING-only flags; kept for the design
pub(super) enum FlagScope {
    Running,
    Stopped,
    Both,
}

impl SystemFlag {
    fn as_str(&self) -> &'static str {
        match self {
            SystemFlag::Failed => "failed",
            SystemFlag::Backoff => "backoff",
            SystemFlag::Outdated => "outdated",
            SystemFlag::UserStop => "user_stop",
            SystemFlag::UserStart => "user_start",
            SystemFlag::OtKilled => "ot_killed",
            SystemFlag::ExitOk => "exit_ok",
            SystemFlag::ExitErr => "exit_err",
            SystemFlag::Dummy1 => "dummy1",
            SystemFlag::Dummy2 => "dummy2",
            SystemFlag::Dummy3 => "dummy3",
            SystemFlag::Dummy4 => "dummy4",
            SystemFlag::Dummy5 => "dummy5",
            SystemFlag::Dummy6 => "dummy6",
            SystemFlag::Dummy7 => "dummy7",
            SystemFlag::Dummy8 => "dummy8",
            SystemFlag::Dummy9 => "dummy9",
            SystemFlag::Dummy10 => "dummy10",
            SystemFlag::SystemStart => "system_start",
            SystemFlag::NoFlag => "no_flag",
            SystemFlag::FlagBug => "flag_bug",
        }
    }

    pub(super) fn scope(&self) -> FlagScope {
        match self {
            // These describe stopped-state conditions only.
            SystemFlag::Failed => FlagScope::Stopped,
            SystemFlag::Backoff => FlagScope::Stopped,
            SystemFlag::OtKilled => FlagScope::Stopped,
            SystemFlag::ExitOk => FlagScope::Stopped,
            SystemFlag::ExitErr => FlagScope::Stopped,
            SystemFlag::Dummy1 => FlagScope::Both,
            SystemFlag::Dummy2 => FlagScope::Both,
            SystemFlag::Dummy3 => FlagScope::Both,
            SystemFlag::Dummy4 => FlagScope::Both,
            SystemFlag::Dummy5 => FlagScope::Both,
            SystemFlag::Dummy6 => FlagScope::Both,
            SystemFlag::Dummy7 => FlagScope::Both,
            SystemFlag::Dummy8 => FlagScope::Both,
            SystemFlag::Dummy9 => FlagScope::Both,
            SystemFlag::Dummy10 => FlagScope::Both,

            // These can be useful in either state (or might be set transiently during transitions).
            SystemFlag::Outdated => FlagScope::Both,
            SystemFlag::UserStop => FlagScope::Stopped,
            SystemFlag::UserStart => FlagScope::Running,
            // Internal/controller-only flags; generally should not be displayed, but scoping doesn't matter much
            // because rules clear them immediately.
            SystemFlag::SystemStart => FlagScope::Running,
            SystemFlag::NoFlag => FlagScope::Both,
            SystemFlag::FlagBug => FlagScope::Both,
        }
    }

    fn parse(s: &str) -> Option<SystemFlag> {
        match s.trim() {
            "failed" => Some(SystemFlag::Failed),
            "backoff" => Some(SystemFlag::Backoff),
            "outdated" => Some(SystemFlag::Outdated),
            "user_stop" => Some(SystemFlag::UserStop),
            "user_start" => Some(SystemFlag::UserStart),
            "ot_killed" => Some(SystemFlag::OtKilled),
            "exit_ok" => Some(SystemFlag::ExitOk),
            "exit_err" => Some(SystemFlag::ExitErr),
            "dummy1" => Some(SystemFlag::Dummy1),
            "dummy2" => Some(SystemFlag::Dummy2),
            "dummy3" => Some(SystemFlag::Dummy3),
            "dummy4" => Some(SystemFlag::Dummy4),
            "dummy5" => Some(SystemFlag::Dummy5),
            "dummy6" => Some(SystemFlag::Dummy6),
            "dummy7" => Some(SystemFlag::Dummy7),
            "dummy8" => Some(SystemFlag::Dummy8),
            "dummy9" => Some(SystemFlag::Dummy9),
            "dummy10" => Some(SystemFlag::Dummy10),
            "system_start" => Some(SystemFlag::SystemStart),
            "no_flag" => Some(SystemFlag::NoFlag),
            "flag_bug" => Some(SystemFlag::FlagBug),
            _ => None,
        }
    }
}

impl std::fmt::Display for SystemFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub(super) fn sysflag_set(map: &mut BTreeMap<SystemFlag, Option<i64>>, flag: SystemFlag, expires_at_ms: Option<i64>) {
    map.insert(flag, expires_at_ms);
}

pub(super) fn sysflag_clear(map: &mut BTreeMap<SystemFlag, Option<i64>>, flag: SystemFlag) {
    map.remove(&flag);
}

pub(super) fn sysflag_has(map: &BTreeMap<SystemFlag, Option<i64>>, flag: SystemFlag) -> bool {
    map.contains_key(&flag)
}

pub(super) fn sysflag_set_with_rules(
    app: &str,
    map: &mut BTreeMap<SystemFlag, Option<i64>>,
    flag: SystemFlag,
    expires_at_ms: Option<i64>,
) {
    // Two-phase rule application:
    // - Evaluate rules on a snapshot (BFS) to compute (1) flags to remove, (2) flags to add/update.
    // - Apply removals first, then apply adds/updates.
    //
    // Conflict resolution: if a flag is both set and cleared by rules, "set wins".
    use std::collections::{HashSet, VecDeque};

    // Rules source (avoid allocating/cloning in the common case).
    let rules_owned;
    let rules: &FlagRulesCompiled = match FLAG_RULES.get() {
        Some(r) => r,
        None => {
            rules_owned = default_flag_rules_compiled();
            &rules_owned
        }
    };

    // Snapshot of existing flags.
    let existing: Vec<SystemFlag> = map.keys().copied().collect();

    // BFS evaluation.
    let mut queue: VecDeque<SystemFlag> = VecDeque::new();
    let mut expanded: HashSet<SystemFlag> = HashSet::new();
    let mut to_clear: std::collections::BTreeSet<SystemFlag> = std::collections::BTreeSet::new();
    // These are flags being applied in this round (the "fresh set" to keep under clears=["*"] semantics).
    let mut applied_set: std::collections::BTreeSet<SystemFlag> = std::collections::BTreeSet::new();
    // Track which flags are requested via also_sets (used to decide whether to insert them if absent).
    let mut also_set_requested: std::collections::BTreeSet<SystemFlag> = std::collections::BTreeSet::new();

    let mut clear_all = false;
    let mut actions: usize = 0;
    applied_set.insert(flag);
    queue.push_back(flag);

    while let Some(f) = queue.pop_front() {
        if actions > 10_000 {
            break;
        }
        if !expanded.insert(f) {
            continue;
        }
        let Some(rule) = rules.get(&f) else { continue };

        if rule.clear_all_except_fresh {
            clear_all = true;
            actions += 1;
        }

        for c in &rule.clears {
            if to_clear.insert(*c) {
                actions += 1;
            }
        }

        for a in &rule.also_sets {
            if also_set_requested.insert(*a) {
                actions += 1;
            }
            // "Apply" the flag in this round (even if it already existed) so its clears/also_sets are evaluated.
            applied_set.insert(*a);
            queue.push_back(*a);
        }
    }

    if actions > 10_000 {
        applied_set.insert(SystemFlag::FlagBug);
        pm_event("flags", Some(app), "decision=stop reason=side_effect_limit_exceeded limit=10000");
    }

    // Expand clears=["*"] as: clear all existing flags except those applied in this round.
    if clear_all {
        let mut n = 0usize;
        for k in &existing {
            if applied_set.contains(k) {
                continue;
            }
            if to_clear.insert(*k) {
                n += 1;
            }
        }
        pm_event(
            "flags",
            Some(app),
            format!("effect=clear_all kept_applied={} clear_candidates={}", applied_set.len(), n),
        );
    }

    // Resolve conflicts: set wins.
    for k in &applied_set {
        to_clear.remove(k);
    }

    // Apply removals.
    for r in to_clear {
        if map.remove(&r).is_some() {
            pm_event("flags", Some(app), format!("effect=clear cleared={}", r.as_str()));
        }
    }

    // Apply adds/updates:
    // - The primary flag is always set/updated with the requested expiry.
    map.insert(flag, expires_at_ms);
    pm_event("flags", Some(app), format!("effect=set flag={}", flag.as_str()));

    // - also_sets are inserted if missing; existing ones are kept as-is.
    for a in also_set_requested {
        if a == flag {
            continue;
        }
        if map.contains_key(&a) {
            continue;
        }
        map.insert(a, None);
        pm_event("flags", Some(app), format!("effect=also_set flag={}", a.as_str()));
    }
}

pub(super) fn default_flag_rules_compiled() -> FlagRulesCompiled {
    // Safe defaults matching current semantics:
    // - user_start implies not user_stop, and clears the "ot_killed" marker (manual intervention acknowledges it).
    // - user_stop implies not user_start.
    let mut m: FlagRulesCompiled = HashMap::new();
    m.insert(
        SystemFlag::UserStart,
        FlagRuleCompiled {
            clear_all_except_fresh: false,
            clears: vec![SystemFlag::UserStop, SystemFlag::OtKilled],
            also_sets: vec![],
        },
    );
    m.insert(
        SystemFlag::UserStop,
        FlagRuleCompiled {
            clear_all_except_fresh: false,
            clears: vec![SystemFlag::UserStart],
            also_sets: vec![],
        },
    );
    m.insert(
        SystemFlag::Failed,
        FlagRuleCompiled {
            clear_all_except_fresh: false,
            clears: vec![SystemFlag::Backoff],
            also_sets: vec![],
        },
    );
    m.insert(
        SystemFlag::SystemStart,
        FlagRuleCompiled {
            clear_all_except_fresh: false,
            // Treat a successful system-triggered start (e.g. boot or config reload) as clearing stale suppression.
            // Do NOT clear UserStop here; callers must respect operator intent separately.
            clears: vec![SystemFlag::Failed, SystemFlag::Backoff, SystemFlag::OtKilled],
            also_sets: vec![],
        },
    );
    m
}

pub(super) fn load_flag_rules(cfg: &MasterConfig) -> FlagRulesCompiled {
    fn compile_from_parsed(parsed: FlagRulesFile) -> FlagRulesCompiled {
        let mut compiled: FlagRulesCompiled = HashMap::new();
        for (k, v) in parsed {
            let Some(flag) = SystemFlag::parse(&k) else {
                pm_event("flags", None, format!("ignore_rule reason=unknown_flag flag={k}"));
                continue;
            };
            let mut clears: Vec<SystemFlag> = vec![];
            let mut clear_all_except_fresh = false;
            for c in v.clears {
                if c.trim() == "*" {
                    clear_all_except_fresh = true;
                    continue;
                }
                if let Some(f) = SystemFlag::parse(&c) {
                    clears.push(f);
                } else {
                    pm_event(
                        "flags",
                        None,
                        format!(
                            "ignore_rule_field reason=unknown_flag parent={} field=clears value={c}",
                            flag.as_str()
                        ),
                    );
                }
            }
            let mut also_sets: Vec<SystemFlag> = vec![];
            for a in v.also_sets {
                if let Some(f) = SystemFlag::parse(&a) {
                    also_sets.push(f);
                } else {
                    pm_event(
                        "flags",
                        None,
                        format!(
                            "ignore_rule_field reason=unknown_flag parent={} field=also_sets value={a}",
                            flag.as_str()
                        ),
                    );
                }
            }
            compiled.insert(
                flag,
                FlagRuleCompiled {
                    clear_all_except_fresh,
                    clears,
                    also_sets,
                },
            );
        }
        compiled
    }

    // 1) Start from embedded JSON (compiled into the binary).
    let embedded_parsed: Option<FlagRulesFile> = match serde_json::from_str(EMBEDDED_FLAG_RULES_JSON) {
        Ok(v) => Some(v),
        Err(e) => {
            pm_event("flags", None, format!("decision=use_builtin_defaults reason=embedded_json_parse_error err={e}"));
            None
        }
    };
    let mut base = embedded_parsed
        .map(compile_from_parsed)
        .unwrap_or_else(default_flag_rules_compiled);

    // 2) Optional on-disk override at <config_directory>/flag_rules.json.
    let path = cfg.config_directory.join("flag_rules.json");
    match std::fs::read_to_string(&path) {
        Ok(text) => match serde_json::from_str::<FlagRulesFile>(&text) {
            Ok(parsed) => {
                base = compile_from_parsed(parsed);
                pm_event("flags", None, format!("loaded source=disk file={} rules={}", path.display(), base.len()));
            }
            Err(e) => {
                pm_event(
                    "flags",
                    None,
                    format!(
                        "decision=keep_embedded reason=json_parse_error file={} err={e}",
                        path.display()
                    ),
                );
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            pm_event("flags", None, format!("loaded source=embedded rules={}", base.len()));
        }
        Err(e) => {
            pm_event(
                "flags",
                None,
                format!("decision=keep_embedded reason=read_error file={} err={e}", path.display()),
            );
        }
    }

    base
}

pub(super) fn start_flag_maintenance_thread(state: Arc<Mutex<DaemonState>>) {
    tasks().spawn(async move {
        loop {
            if state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .shutting_down
                .load(Ordering::Relaxed)
            {
                break;
            }

            let now_ms = Local::now().timestamp_millis();
            let (run_info, events) = {
                let st = state.lock().unwrap_or_else(|p| p.into_inner());
                (Arc::clone(&st.run_info), Arc::clone(&st.events))
            };

            let mut expired_pairs: Vec<(String, String)> = vec![];
            let mut expired_user_any = false;
            let mut next_deadline_ms: Option<i64> = None;
            {
                let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                for (app, info) in ri.iter_mut() {
                    // system flags
                    let mut to_remove_sys: Vec<SystemFlag> = vec![];
                    for (k, v) in info.system_flags.iter() {
                        if let Some(deadline) = v {
                            if now_ms >= *deadline {
                                to_remove_sys.push(*k);
                            } else {
                                next_deadline_ms = Some(match next_deadline_ms {
                                    None => *deadline,
                                    Some(cur) => cur.min(*deadline),
                                });
                            }
                        }
                    }
                    for k in to_remove_sys {
                        info.system_flags.remove(&k);
                        expired_pairs.push((app.clone(), k.to_string()));
                    }

                    let mut to_remove: Vec<String> = vec![];
                    for (k, v) in info.user_flags.iter() {
                        if let Some(deadline) = v {
                            if now_ms >= *deadline {
                                to_remove.push(k.clone());
                            } else {
                                next_deadline_ms = Some(match next_deadline_ms {
                                    None => *deadline,
                                    Some(cur) => cur.min(*deadline),
                                });
                            }
                        }
                    }
                    for k in to_remove {
                        info.user_flags.remove(&k);
                        expired_pairs.push((app.clone(), k));
                        expired_user_any = true;
                    }
                }
            }

            let had_expired = !expired_pairs.is_empty();
            for (app, flag) in expired_pairs {
                push_event(&events, "flag", Some(&app), format!("expired flag={flag}"));
            }
            // Persisted state is user flags only; system flags must not trigger writes.
            if had_expired && expired_user_any {
                let dirty = {
                    let st = state.lock().unwrap_or_else(|p| p.into_inner());
                    Arc::clone(&st.appstate_dirty)
                };
                dirty.store(true, Ordering::Relaxed);
            }

            // Sleep until the next known expiry (clamped), or back off when nothing has TTL.
            let sleep_ms: u64 = match next_deadline_ms {
                None => 5_000,
                Some(d) => {
                    let dt = (d - now_ms).max(1) as u64;
                    // Clamp: avoid ultra-tight loops and avoid sleeping too long if clocks jump.
                    dt.clamp(50, 5_000)
                }
            };
            tokio_time::sleep(Duration::from_millis(sleep_ms)).await;
        }
    });
}

pub(super) fn parse_flag_ttl_ms(spec: &str) -> anyhow::Result<u64> {
    let t = spec.trim();
    anyhow::ensure!(!t.is_empty(), "empty ttl");
    anyhow::ensure!(!t.chars().any(|c| c.is_whitespace()), "ttl must not contain whitespace");
    let s = t.to_ascii_lowercase();

    // Units must be specified from larger to smaller; no repeats.
    // Supported: d, h, m, s, ms
    // Rank: d(5) > h(4) > m(3) > s(2) > ms(1)
    fn rank(unit: &str) -> Option<u8> {
        match unit {
            "d" => Some(5),
            "h" => Some(4),
            "m" => Some(3),
            "s" => Some(2),
            "ms" => Some(1),
            _ => None,
        }
    }
    fn mult(unit: &str) -> u64 {
        match unit {
            "d" => 86_400_000,
            "h" => 3_600_000,
            "m" => 60_000,
            "s" => 1_000,
            "ms" => 1,
            _ => 1,
        }
    }

    let mut i = 0usize;
    let b = s.as_bytes();
    let mut prev_rank: u8 = 255;
    let mut seen_mask: u8 = 0;
    let mut total: u64 = 0;

    while i < b.len() {
        // number
        let start = i;
        while i < b.len() && (b[i] as char).is_ascii_digit() {
            i += 1;
        }
        anyhow::ensure!(i > start, "ttl: expected number at offset {}", start);
        let num: u64 = s[start..i].parse()?;

        // unit
        anyhow::ensure!(i < b.len(), "ttl: missing unit after {}", num);
        let unit = if s[i..].starts_with("ms") {
            i += 2;
            "ms"
        } else {
            let ch = b[i] as char;
            anyhow::ensure!(matches!(ch, 'd' | 'h' | 'm' | 's'), "ttl: invalid unit at offset {}", i);
            i += 1;
            match ch {
                'd' => "d",
                'h' => "h",
                'm' => "m",
                's' => "s",
                _ => unreachable!(),
            }
        };

        let r = rank(unit).unwrap();
        anyhow::ensure!(r < prev_rank, "ttl: units must go from larger to smaller (e.g. 3h1m); got ...{unit} after smaller/equal unit");
        let bit = 1u8 << (r - 1);
        anyhow::ensure!((seen_mask & bit) == 0, "ttl: unit {unit} repeated");
        seen_mask |= bit;
        prev_rank = r;

        let add = num.checked_mul(mult(unit)).ok_or_else(|| anyhow::anyhow!("ttl overflow"))?;
        total = total.checked_add(add).ok_or_else(|| anyhow::anyhow!("ttl overflow"))?;
    }
    Ok(total)
}

/// Flags are echoed into the event log and the web UI. Restricting them to a plain
/// token alphabet keeps a newline (a forged audit line) or markup out of both.
pub(super) fn validate_flag_chars(flag: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        flag.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b':' | b'-')),
        "flag {flag:?} may only contain [a-z0-9_.:-]"
    );
    Ok(())
}
