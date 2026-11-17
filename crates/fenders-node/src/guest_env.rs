//! The launcher's fixed guest environment region is 4096 bytes. Validate the
//! exact encoding before allocating a worker, and use the same bytes at launch.
use fenders_node_protocol::{
    error::{Error, Result},
    value::{n, s},
};
use serde_json::{Value, json};

pub fn public_targets(spec: &Value) -> Result<fenders_egress::PublicTargets> {
    let policy = match spec.get("http_public_targets") {
        None => "",
        Some(value) => value
            .as_str()
            .ok_or_else(|| Error::invalid("invalid public HTTPS targets"))?,
    };
    let targets = fenders_egress::PublicTargets::parse(policy)
        .map_err(|_| Error::invalid("invalid public HTTPS targets"))?;
    for (origin, addresses) in targets.iter() {
        if !spec["http_allow"]
            .as_array()
            .is_some_and(|v| v.contains(&json!(origin.to_string())))
            || spec["http_trust"].get(origin.to_string()).is_some()
            || addresses.iter().any(|address| {
                !spec["tcp_allow"]
                    .as_array()
                    .is_some_and(|v| v.contains(&json!(address.to_string())))
            })
        {
            return Err(Error::invalid(
                "public HTTPS targets require exact origins, TCP ceilings and public trust",
            ));
        }
    }
    Ok(targets)
}

pub fn http_roots(spec: &Value) -> Result<String> {
    let Some(value) = spec.get("http_trust") else {
        return Ok(String::new());
    };
    let map = value
        .as_object()
        .filter(|m| m.len() <= 32)
        .ok_or_else(|| Error::invalid("invalid HTTPS trust map"))?;
    let mut entries = Vec::new();
    for (origin, hex) in map {
        if !spec["http_allow"]
            .as_array()
            .is_some_and(|a| a.contains(&json!(origin)))
        {
            return Err(Error::invalid(
                "HTTPS trust requires an allowed exact origin",
            ));
        }
        let hex = hex
            .as_str()
            .ok_or_else(|| Error::invalid("invalid HTTPS CA"))?;
        entries.push(format!("{origin}={hex}"));
    }
    let policy = entries.join(";");
    for (_, der) in fenders_service_trust::parse(&policy)
        .map_err(|_| Error::invalid("invalid or oversized HTTPS trust map"))?
    {
        fenders_node_protocol::transport::validate_ca_der(&der)?;
    }
    Ok(policy)
}

pub fn encode(spec: &Value) -> Result<Vec<u8>> {
    let mut guest = spec["env"].as_object().ok_or_else(Error::internal)?.clone();
    // Configuration cannot name a reserved variable; the run context alone adds these.
    if let Some(context) = spec.get("run_context") {
        for (name, value) in fenders_node_protocol::workloads::run_context_env(context) {
            guest.insert(name.into(), json!(value));
        }
    }
    let targets = public_targets(spec)?;
    let public_endpoints: std::collections::BTreeSet<_> = targets
        .iter()
        .flat_map(|(_, addresses)| addresses.iter().map(ToString::to_string))
        .collect();
    for (key, value) in [
        ("FENDERS_MODE", s(&spec["mode"]).to_owned()),
        ("FENDERS_FS_PREOPENS", String::new()),
        ("FENDERS_FUEL", n(&spec["fuel"]).to_string()),
        (
            "FENDERS_WASM_MEMORY_BYTES",
            (n(&spec["wasm_memory_mib"]) * 1024 * 1024).to_string(),
        ),
        (
            "FENDERS_HTTP_ALLOW",
            spec["http_allow"]
                .as_array()
                .ok_or_else(Error::internal)?
                .iter()
                .map(s)
                .collect::<Vec<_>>()
                .join(","),
        ),
        ("FENDERS_HTTP_SERVICE_ROOTS", http_roots(spec)?),
        ("FENDERS_HTTP_PUBLIC_TARGETS", targets.encode()),
        (
            "FENDERS_SOCKET_ALLOW",
            spec["tcp_allow"]
                .as_array()
                .ok_or_else(Error::internal)?
                .iter()
                .map(s)
                // A public HTTPS permission must not also grant raw sockets.
                .filter(|address| !public_endpoints.contains(*address))
                .collect::<Vec<_>>()
                .join(","),
        ),
        (
            "FENDERS_REQUEST_TIMEOUT_MS",
            n(&spec["request_timeout_ms"]).to_string(),
        ),
    ] {
        guest.insert(key.into(), json!(value));
    }
    if let Some(kib) = spec.get("wasm_stack_kib") {
        guest.insert(
            "FENDERS_WASM_STACK_BYTES".into(),
            json!((n(kib) * 1024).to_string()),
        );
    }
    for (key, field) in [
        ("FENDERS_HOST_ORIGIN", "host_origin"),
        ("FENDERS_FUEL_REFUEL", "fuel_refuel"),
        ("FENDERS_INSTANCES", "instances"),
        ("FENDERS_TABLE_ELEMENTS", "table_elements"),
        ("FENDERS_TABLES", "tables"),
        ("FENDERS_MEMORIES", "memories"),
        ("FENDERS_HTTP_CONCURRENCY", "http_concurrency"),
    ] {
        if let Some(value) = spec.get(field) {
            let value = value
                .as_str()
                .map_or_else(|| n(value).to_string(), str::to_owned);
            guest.insert(key.into(), json!(value));
        }
    }
    let mut bytes = Vec::new();
    for (key, value) in guest {
        bytes.extend_from_slice(format!("{key}={}\0", s(&value)).as_bytes());
    }
    if bytes.len() > fenders_service_trust::MAX_GUEST_ENV_BYTES {
        return Err(Error::invalid(
            "configuration and network policy exceed the 4096-byte guest environment limit",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::validate_spec;
    fn ca() -> String {
        use base64::Engine;
        let root = tempfile::tempdir().unwrap();
        fenders_control_plane::pki::create(root.path(), &Default::default()).unwrap();
        let base64 = std::fs::read_to_string(root.path().join("ca.pem"))
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with('-'))
            .collect::<String>();
        base64::engine::general_purpose::STANDARD
            .decode(base64)
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
    #[test]
    fn trust_is_bounded_validated_and_only_for_allowed_https_origins() {
        let hex = ca();
        let source = json!({"artifact":"a".repeat(64),"http_allow":["https://10.50.0.2:8443","https://public.test"],"http_trust":{"https://10.50.0.2:8443":hex},"env":{"MODE":"test"}});
        let spec = validate_spec(&source).unwrap();
        let bytes = encode(&spec).unwrap();
        let records = bytes
            .split(|b| *b == 0)
            .filter(|v| !v.is_empty())
            .map(|b| std::str::from_utf8(b).unwrap())
            .collect::<Vec<_>>();
        assert!(records.contains(
            &format!("FENDERS_HTTP_SERVICE_ROOTS=https://10.50.0.2:8443={hex}").as_str()
        ));
        assert!(records.contains(&"FENDERS_FS_PREOPENS="));
        assert!(records.contains(&"MODE=test"));
        assert!(
            !records
                .iter()
                .any(|r| r.starts_with("FENDERS_HTTP_CA_DER_HEX="))
        );
        for trust in [
            json!([]),
            json!({"https://10.50.0.2:8443":"00"}),
            json!({"https://other.test:443":hex}),
            json!({"https://10.50.0.2:8443":5}),
            json!({"http://10.50.0.2:8443":hex}),
        ] {
            let mut invalid = source.clone();
            invalid["http_trust"] = trust;
            assert!(validate_spec(&invalid).is_err());
        }
        let mut invalid = source;
        invalid["env"]["FENDERS_HTTP_SERVICE_ROOTS"] = json!("override");
        assert!(validate_spec(&invalid).is_err());
    }
    #[test]
    fn an_http_run_is_told_how_many_requests_to_serve_at_once_when_they_fit() {
        let source = |mode: &str, concurrency: i64, guest: i64, wasm: i64| {
            json!({"artifact":"a".repeat(64),"mode":mode,"guest_memory_mib":guest,
                "wasm_memory_mib":wasm,"http_concurrency":concurrency,"env":{}})
        };
        let variable = |spec: &Value| {
            let bytes = encode(spec).unwrap();
            bytes
                .split(|b| *b == 0)
                .map(|record| String::from_utf8_lossy(record).into_owned())
                .find(|record| record.starts_with("FENDERS_HTTP_CONCURRENCY="))
        };
        // Four stores of 8 MiB fit a 96 MiB guest ((96 - 16) / 2 = 40).
        let spec = validate_spec(&source("http", 4, 96, 8)).unwrap();
        assert_eq!(spec["http_concurrency"], 4);
        assert_eq!(
            variable(&spec).as_deref(),
            Some("FENDERS_HTTP_CONCURRENCY=4")
        );
        // Six do not; a command serves no requests; the number is bounded.
        assert!(validate_spec(&source("http", 6, 96, 8)).is_err());
        assert!(validate_spec(&source("command", 2, 96, 8)).is_err());
        assert!(validate_spec(&source("http", 0, 96, 8)).is_err());
        assert!(validate_spec(&source("http", 65, 1024, 1)).is_err());
        // A spec that does not say is told nothing.
        let plain = validate_spec(&json!({"artifact":"a".repeat(64),"mode":"http"})).unwrap();
        assert!(plain.get("http_concurrency").is_none());
        assert_eq!(variable(&plain), None);
    }

    #[test]
    fn run_context_reaches_the_app_only_as_documented_variables() {
        let records = |source: Value| {
            let bytes = encode(&validate_spec(&source).unwrap()).unwrap();
            bytes
                .split(|b| *b == 0)
                .filter(|v| !v.is_empty())
                .map(|b| std::str::from_utf8(b).unwrap().to_owned())
                .collect::<Vec<_>>()
        };
        let run = "b".repeat(32);
        let scheduled = records(
            json!({"artifact":"a".repeat(64),"run_context":{"trigger":"schedule","trigger_time":"2026-10-21T09:00:00+02:00","run_id":run,"schedule":"0 9 * * 1-5","schedule_timezone":"Europe/Zagreb"}}),
        );
        for expected in [
            "FENDERS_TRIGGER=schedule".to_owned(),
            "FENDERS_TRIGGER_TIME=2026-10-21T07:00:00Z".to_owned(),
            format!("FENDERS_RUN_ID={run}"),
            "FENDERS_SCHEDULE=0 9 * * 1-5".to_owned(),
            "FENDERS_SCHEDULE_TIMEZONE=Europe/Zagreb".to_owned(),
        ] {
            assert!(scheduled.contains(&expected), "{expected} in {scheduled:?}");
        }
        let manual = records(
            json!({"artifact":"a".repeat(64),"run_context":{"trigger":"manual","trigger_time":"2026-10-21T09:14:00Z","run_id":run}}),
        );
        assert!(manual.contains(&"FENDERS_TRIGGER=manual".to_owned()));
        assert!(!manual.iter().any(|r| r.starts_with("FENDERS_SCHEDULE")));
        let none = records(json!({"artifact":"a".repeat(64)}));
        assert!(
            !none
                .iter()
                .any(|r| r.starts_with("FENDERS_TRIGGER") || r.starts_with("FENDERS_RUN_ID"))
        );
    }
    #[test]
    fn exact_environment_limit_includes_internal_policy_and_terminators() {
        let mut source = json!({"artifact":"a".repeat(64),"env":{"PADDING":""},"http_allow":(0..20).map(|i|format!("https://{}.h{i}.test:8443", "x".repeat(60))).collect::<Vec<_>>(),"tcp_allow":(1..=32).map(|i|format!("10.50.0.{i}:5432")).collect::<Vec<_>>()});
        let initial = encode(&validate_spec(&source).unwrap()).unwrap();
        let remaining = fenders_service_trust::MAX_GUEST_ENV_BYTES - initial.len();
        assert!(remaining < 1900);
        source["env"]["PADDING"] = json!("x".repeat(remaining));
        let spec = validate_spec(&source).unwrap();
        assert_eq!(
            encode(&spec).unwrap().len(),
            fenders_service_trust::MAX_GUEST_ENV_BYTES
        );
        source["env"]["PADDING"] = json!("x".repeat(remaining + 1));
        assert!(validate_spec(&source).is_err());
        let empty = validate_spec(&json!({"artifact":"a".repeat(64)})).unwrap();
        assert!(
            encode(&empty)
                .unwrap()
                .split(|b| *b == 0)
                .any(|line| line == b"FENDERS_HTTP_SERVICE_ROOTS=")
        );
    }

    #[test]
    fn public_https_targets_are_static_policy_and_do_not_authorize_wasi_sockets() {
        let source = json!({"artifact":"a".repeat(64),"env":{},
            "http_allow":["https://api.example.com:443","https://10.50.0.2:8443"],
            "http_public_targets":"https://api.example.com:443=1.1.1.1,8.8.8.8",
            "http_runtime_digest":"a".repeat(64),
            "tcp_allow":["1.1.1.1:443","8.8.8.8:443","10.50.0.2:5432","10.50.0.2:8443"]});
        #[cfg(target_os = "linux")]
        let checked = validate_spec(&source).unwrap();
        #[cfg(not(target_os = "linux"))]
        let checked = source.clone();
        let bytes = encode(&checked).unwrap();
        let records = bytes.split(|b| *b == 0).collect::<Vec<_>>();
        assert!(records.contains(
            &b"FENDERS_HTTP_PUBLIC_TARGETS=https://api.example.com:443=1.1.1.1,8.8.8.8".as_slice()
        ));
        assert!(
            records.contains(&b"FENDERS_SOCKET_ALLOW=10.50.0.2:5432,10.50.0.2:8443".as_slice())
        );
        // The independent VMM still receives the whole immutable TCP ceiling.
        assert_eq!(checked["tcp_allow"].as_array().unwrap().len(), 4);
        for (key, value) in [
            ("tcp_allow", json!(["1.1.1.1:443"])),
            ("http_allow", json!(["https://elsewhere.example.com"])),
            ("http_trust", json!({"https://api.example.com:443":ca()})),
            (
                "http_public_targets",
                json!("https://api.example.com:443=169.254.169.254"),
            ),
            ("http_public_targets", json!({})),
        ] {
            let mut invalid = source.clone();
            invalid[key] = value;
            assert!(encode(&invalid).is_err(), "{key}");
            #[cfg(target_os = "linux")]
            assert!(validate_spec(&invalid).is_err(), "{key}");
        }
        assert!(
            validate_spec(
                &json!({"artifact":"a".repeat(64),"env":{"FENDERS_HTTP_PUBLIC_TARGETS":"override"}})
            )
            .is_err()
        );
        let empty = validate_spec(&json!({"artifact":"a".repeat(64)})).unwrap();
        assert!(
            encode(&empty)
                .unwrap()
                .split(|b| *b == 0)
                .any(|line| line == b"FENDERS_HTTP_PUBLIC_TARGETS=")
        );
    }
}
