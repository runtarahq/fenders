//! Execution state and the workload specification a node accepts.
use crate::{
    error::{Error, Result},
    model::*,
    value::*,
};
use serde_json::{Value, json};

pub fn terminal(state: &str) -> bool {
    matches!(state, "exited" | "failed" | "stopped" | "lost")
}
pub fn env_name(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with("FENDERS_")
        && (s.as_bytes()[0].is_ascii_alphabetic() || s.starts_with('_'))
        && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
}
/// Why a command run started. It travels apart from `env`, which may never name
/// a reserved variable, and reaches the app only as the documented names below.
pub fn run_context(value: &Value) -> Result<Value> {
    const SCHEDULE: &[&str] = &[
        "trigger",
        "trigger_time",
        "run_id",
        "schedule",
        "schedule_timezone",
    ];
    let invalid = || Error::invalid("invalid run context");
    let scheduled = match value.get("trigger").and_then(Value::as_str) {
        Some("manual") => false,
        Some("schedule") => true,
        _ => return Err(invalid()),
    };
    fields(
        value,
        if scheduled { SCHEDULE } else { &SCHEDULE[..3] },
        if scheduled { SCHEDULE } else { &SCHEDULE[..3] },
    )
    .map_err(|_| invalid())?;
    let time = chrono::DateTime::parse_from_rfc3339(text(&value["trigger_time"])?)
        .map_err(|_| invalid())?
        .with_timezone(&chrono::Utc);
    let run = text(&value["run_id"])?;
    identity(run).map_err(|_| invalid())?;
    let mut out = json!({
        "trigger": value["trigger"],
        "trigger_time": time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "run_id": run,
    });
    if scheduled {
        let schedule = crate::schedule::Schedule::parse(
            text(&value["schedule"])?,
            text(&value["schedule_timezone"])?,
        )?;
        out["schedule"] = json!(schedule.expression);
        out["schedule_timezone"] = json!(schedule.timezone.name());
    }
    Ok(out)
}
/// The reserved variables a validated run context gives the app.
pub fn run_context_env(context: &Value) -> Vec<(&'static str, String)> {
    [
        ("FENDERS_TRIGGER", "trigger"),
        ("FENDERS_TRIGGER_TIME", "trigger_time"),
        ("FENDERS_RUN_ID", "run_id"),
        ("FENDERS_SCHEDULE", "schedule"),
        ("FENDERS_SCHEDULE_TIMEZONE", "schedule_timezone"),
    ]
    .into_iter()
    .filter_map(|(name, key)| Some((name, context.get(key)?.as_str()?.to_owned())))
    .collect()
}
/// The largest aggregate linear memory a guest of this size admits. The runtime
/// keeps 16 MiB, and a growing memory moves, briefly holding both copies.
pub fn wasm_memory_limit_mib(guest_memory_mib: i64) -> i64 {
    (guest_memory_mib - 16) / 2
}
pub fn wasm_spec(value: &Value, service: bool) -> Result<Value> {
    fields(
        value,
        &[
            "artifact_id",
            "mode",
            "cpu_percent",
            "guest_memory_mib",
            "host_memory_mib",
            "wasm_memory_mib",
            "fuel",
            "fuel_refuel",
            "instances",
            "table_elements",
            "tables",
            "memories",
            "wasm_stack_kib",
            "lifetime_seconds",
            "request_timeout_ms",
            "http_concurrency",
            "env",
            "secret_env",
            "architecture",
            "runtime",
            "restart_policy",
            "network_id",
            "endpoint_ids",
            "endpoint_env",
        ],
        &["artifact_id"],
    )?;
    id(&value["artifact_id"])?;
    let mut out = value.clone();
    out["mode"] = get(
        value,
        "mode",
        json!(if service { "http" } else { "command" }),
    );
    if !matches!(s(&out["mode"]), "http" | "command") || service && out["mode"] != "http" {
        return Err(Error::invalid("invalid execution mode"));
    }
    // Guest RAM is mapped in 2 MiB pages, up to the 1 GiB one page directory maps.
    let guest = integer(&get(value, "guest_memory_mib", json!(32)), 32, 1024)?;
    if guest % 2 != 0 {
        return Err(Error::invalid("guest memory must be a multiple of 2 MiB"));
    }
    // Left out when absent, so earlier specs normalize unchanged and older nodes accept them.
    if value.get("guest_memory_mib").is_some() {
        out["guest_memory_mib"] = json!(guest);
    }
    for (field, default, low, high) in [
        ("cpu_percent", 100, 1, 100),
        ("host_memory_mib", guest + 32, guest + 16, guest + 480),
        ("wasm_memory_mib", 4, 1, wasm_memory_limit_mib(guest)),
        ("fuel", 200000000, 10000, 2000000000),
        ("lifetime_seconds", 86400, 1, 86400),
        ("request_timeout_ms", 10000, 100, 60000),
    ] {
        out[field] = json!(integer(&get(value, field, json!(default)), low, high)?);
    }
    // Structural limits are carried only when a spec sets them, like guest memory.
    for (field, low, high) in [
        ("instances", 1, 1000),
        ("table_elements", 1, 1_000_000),
        ("tables", 1, 1000),
        ("memories", 1, 1000),
        // The host stack wasm may use (wasmtime's `max_wasm_stack`), for a
        // guest that recurses deeply, such as a compiler; 512 KiB when unset.
        ("wasm_stack_kib", 512, 65536),
    ] {
        if let Some(limit) = value.get(field) {
            out[field] = json!(integer(limit, low, high)?);
        }
    }
    // The requests an HTTP run's guest serves at once, each in a store with
    // the run's linear memory limit: they must fit the guest together.
    // Carried only when a spec sets it; one otherwise.
    if let Some(concurrency) = value.get("http_concurrency") {
        let concurrency = integer(concurrency, 1, 64)?;
        if out["mode"] != "http" {
            return Err(Error::invalid("only an HTTP run serves requests at once"));
        }
        if concurrency * n(&out["wasm_memory_mib"]) > wasm_memory_limit_mib(guest) {
            return Err(Error::invalid(
                "the guest's memory does not hold that many requests at once",
            ));
        }
        out["http_concurrency"] = json!(concurrency);
    }
    if value
        .get("fuel_refuel")
        .is_some_and(|refuel| !matches!(refuel.as_str(), Some("off" | "yield")))
    {
        return Err(Error::invalid("fuel refuelling must be off or yield"));
    }
    for field in ["env", "secret_env"] {
        out[field] = get(value, field, json!({}));
        let env = out[field]
            .as_object()
            .ok_or_else(|| Error::invalid("invalid environment"))?;
        if env.len() > 32 {
            return Err(Error::invalid("too many environment entries"));
        }
        for (key, val) in env {
            if !env_name(key) || text(val)?.contains('\0') {
                return Err(Error::invalid("invalid environment"));
            }
            if field == "secret_env" {
                id(val)?;
            }
        }
    }
    if out["env"]
        .as_object()
        .unwrap()
        .keys()
        .any(|k| out["secret_env"].get(k).is_some())
        || serde_json::to_vec(&out["env"]).unwrap().len() > 2048
    {
        return Err(Error::invalid("conflicting or oversized environment"));
    }
    out["architecture"] = get(value, "architecture", json!("x86_64"));
    out["runtime"] = get(value, "runtime", json!("wasmtime-50.0.0-fenders-v1"));
    if out["architecture"] != "x86_64" || out["runtime"] != "wasmtime-50.0.0-fenders-v1" {
        return Err(Error::invalid("unsupported architecture or runtime"));
    }
    out["restart_policy"] = get(value, "restart_policy", json!("never"));
    if !matches!(s(&out["restart_policy"]), "never" | "always")
        || !service && out["restart_policy"] != "never"
    {
        return Err(Error::invalid(
            "automatic replacement requires an opted-in HTTP deployment",
        ));
    }
    if ["network_id", "endpoint_ids", "endpoint_env"]
        .iter()
        .any(|k| value.get(k).is_some())
    {
        id(&value["network_id"])?;
        let services = get(value, "endpoint_ids", json!([]));
        let mut services = services
            .as_array()
            .ok_or_else(|| Error::invalid("invalid service IDs"))?
            .clone();
        for service in &services {
            id(service)?;
        }
        services.sort_by(|a, b| s(a).cmp(s(b)));
        if services.len() > 32 || services.windows(2).any(|v| v[0] == v[1]) {
            return Err(Error::invalid("expected at most 32 distinct services"));
        }
        let bindings = get(value, "endpoint_env", json!({}));
        let bindings = bindings
            .as_object()
            .ok_or_else(|| Error::invalid("invalid service bindings"))?;
        if bindings.len()
            + out["env"].as_object().unwrap().len()
            + out["secret_env"].as_object().unwrap().len()
            > 32
        {
            return Err(Error::invalid("too many environment entries"));
        }
        for (key, binding) in bindings {
            fields(
                binding,
                &["endpoint_id", "field"],
                &["endpoint_id", "field"],
            )?;
            if !env_name(key)
                || !services.contains(&binding["endpoint_id"])
                || !matches!(
                    s(&binding["field"]),
                    "host" | "port" | "url" | "ca_certificate"
                )
                || out["env"].get(key).is_some()
                || out["secret_env"].get(key).is_some()
            {
                return Err(Error::invalid("invalid service environment binding"));
            }
        }
        out["endpoint_ids"] = json!(services);
        out["endpoint_env"] = json!(bindings);
    }
    Ok(out)
}
