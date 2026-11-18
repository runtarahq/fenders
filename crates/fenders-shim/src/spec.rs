//! The run spec a launcher hands the shim on its standard input.
//!
//! It carries the run channel's credential, so nothing here derives `Debug`
//! and nothing prints a spec or its channel.
use serde_json::Value;
use std::path::PathBuf;

/// The largest spec read from standard input.
pub const MAX_SPEC_BYTES: usize = 1024 * 1024;
/// The run protocol version this shim speaks.
pub const PROTOCOL: i64 = 1;

pub struct Spec {
    pub run: Run,
    pub channel: Channel,
    /// The launcher holding the run over its link, if any (a node's agent).
    pub launcher: Option<Launcher>,
    pub machine: Machine,
}

/// What a run runs on, known before the run: a warm shim starts its VM from
/// this alone and is claimed for a run later ([`Spec::claim`]).
pub struct Machine {
    /// The compiled component (`.cwasm`) for this host's runtime.
    pub component: PathBuf,
    /// The component's SHA-256, checked when given.
    pub component_sha256: Option<String>,
    /// Holds `launch` and `runtime.elf`; the shim's own directory by default.
    pub runtime_dir: Option<PathBuf>,
    /// The uid and gid the run drops to when the shim starts as root.
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    /// The host CPU the VMM is pinned to; the first allowed one by default.
    pub cpu: Option<usize>,
    /// Whether the VM may share a core with another run's at the same
    /// moment. Unless told so, it has a core-scheduling cookie of its own.
    pub share_core: bool,
    /// The guest's configuration, normalized as a node launch spec.
    pub guest: Value,
}

/// A launcher that tracks the run over [`crate::link`].
pub struct Launcher {
    /// The run's id on its launcher, which names its link.
    pub id: String,
    /// What the launcher created the run for (its idempotency key).
    pub key: String,
    /// The only uid the link answers.
    pub uid: u32,
}

pub struct Run {
    pub execution: String,
    pub generation: u64,
    pub trace_id: Option<String>,
}

pub struct Channel {
    /// `https://host[:port][/prefix]`, without a trailing slash.
    pub endpoint: url::Url,
    /// The per-launch bearer credential. Never logged.
    pub credential: String,
    /// PEM certificates the endpoint's chain must lead to.
    pub ca_pem: String,
    /// Hex SHA-256 of the endpoint certificate's SubjectPublicKeyInfo, if pinned.
    pub pin: Option<String>,
    /// The name the endpoint's certificate is for, when not the endpoint's
    /// host (an internal address serving a service certificate).
    pub server_name: Option<String>,
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value, String> {
    value
        .get(name)
        .ok_or_else(|| format!("spec: missing {name}"))
}

fn string(value: &Value, name: &str) -> Result<String, String> {
    field(value, name)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("spec: {name} must be a string"))
}

fn optional_string(value: &Value, name: &str) -> Result<Option<String>, String> {
    match value.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => string(value, name).map(Some),
    }
}

fn only(value: &Value, allowed: &[&str], what: &str) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("spec: {what} must be an object"))?;
    match object.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(unknown) => Err(format!("spec: unknown field {what}.{unknown}")),
        None => Ok(()),
    }
}

fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn id(value: u64) -> Option<u32> {
    u32::try_from(value).ok().filter(|v| *v != 0)
}

fn json(bytes: &[u8]) -> Result<Value, String> {
    serde_json::from_slice(bytes).map_err(|_| "spec: not JSON".to_owned())
}

fn protocol(value: &Value) -> Result<(), String> {
    if field(value, "protocol")?.as_i64() != Some(PROTOCOL) {
        return Err(format!("spec: protocol must be {PROTOCOL}"));
    }
    Ok(())
}

impl Spec {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let value = json(bytes)?;
        only(
            &value,
            &[
                "protocol",
                "run",
                "channel",
                "artifact",
                "runtime",
                "uid",
                "gid",
                "cpu",
                "guest",
                "launcher",
                "share_core",
            ],
            "spec",
        )?;
        protocol(&value)?;
        let machine = Machine::from_value(&value)?;
        Self::with_run(machine, &value)
    }

    /// A warm shim's spec: the machine alone, with `"warm": true`.
    pub fn parse_warm(bytes: &[u8]) -> Result<Machine, String> {
        let value = json(bytes)?;
        only(
            &value,
            &[
                "protocol",
                "warm",
                "artifact",
                "runtime",
                "uid",
                "gid",
                "cpu",
                "guest",
                "share_core",
            ],
            "warm spec",
        )?;
        protocol(&value)?;
        if value["warm"] != true {
            return Err("spec: a warm spec says \"warm\": true".into());
        }
        let machine = Machine::from_value(&value)?;
        // A warm VM waits for its run before it runs anything; an HTTP run's
        // guest serves as soon as its component is loaded.
        if machine.guest["mode"] != "command" {
            return Err("spec: only a command can be started warm".into());
        }
        Ok(machine)
    }

    /// The run a warm machine is claimed for: `run`, `channel` and `launcher`.
    pub fn claim(machine: Machine, bytes: &[u8]) -> Result<Self, String> {
        let value = json(bytes)?;
        only(&value, &["run", "channel", "launcher"], "claim")?;
        Self::with_run(machine, &value)
    }

    fn with_run(machine: Machine, value: &Value) -> Result<Self, String> {
        let run = field(value, "run")?;
        only(run, &["execution", "generation", "trace_id"], "run")?;
        let execution = string(run, "execution")?;
        if execution.is_empty()
            || execution.len() > 128
            || !execution
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("spec: run.execution must be 1-128 of [A-Za-z0-9_-]".into());
        }
        let generation = field(run, "generation")?
            .as_u64()
            .ok_or("spec: run.generation must be a non-negative integer")?;
        let trace_id = optional_string(run, "trace_id")?;
        if trace_id.as_ref().is_some_and(|t| {
            t.is_empty()
                || t.len() > 128
                || !t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        }) {
            return Err("spec: run.trace_id must be 1-128 of [A-Za-z0-9-]".into());
        }

        let channel = field(value, "channel")?;
        only(channel, &["endpoint", "credential", "trust"], "channel")?;
        let mut endpoint = url::Url::parse(&string(channel, "endpoint")?)
            .map_err(|_| "spec: channel.endpoint is not a URL".to_owned())?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err("spec: channel.endpoint must be https://host[:port][/path]".into());
        }
        let prefix = endpoint.path().trim_end_matches('/').to_owned();
        endpoint.set_path(&prefix);
        let credential = string(channel, "credential")?;
        if credential.is_empty()
            || credential.len() > 4096
            || !credential.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err("spec: channel.credential must be 1-4096 visible ASCII characters".into());
        }
        let trust = field(channel, "trust")?;
        only(trust, &["ca_pem", "pin", "server_name"], "channel.trust")?;
        let ca_pem = string(trust, "ca_pem")?;
        let pin = optional_string(trust, "pin")?;
        let server_name = optional_string(trust, "server_name")?;
        if pin.as_deref().is_some_and(|p| !hex64(p)) {
            return Err("spec: channel.trust.pin must be a lowercase hex SHA-256".into());
        }

        let launcher = match value.get("launcher") {
            None | Some(Value::Null) => None,
            Some(launcher) => {
                only(launcher, &["id", "key", "uid"], "launcher")?;
                let id = string(launcher, "id")?;
                if id.is_empty()
                    || id.len() > 64
                    || !id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return Err("spec: launcher.id must be 1-64 of [A-Za-z0-9_-]".into());
                }
                let key = string(launcher, "key")?;
                if key.len() > 128 {
                    return Err("spec: launcher.key is too long".into());
                }
                let uid = field(launcher, "uid")?
                    .as_u64()
                    .and_then(|u| u32::try_from(u).ok())
                    .ok_or("spec: launcher.uid must be a uid")?;
                Some(Launcher { id, key, uid })
            }
        };
        Ok(Self {
            run: Run {
                execution,
                generation,
                trace_id,
            },
            channel: Channel {
                endpoint,
                credential,
                ca_pem,
                pin,
                server_name,
            },
            launcher,
            machine,
        })
    }
}

impl Machine {
    fn from_value(value: &Value) -> Result<Self, String> {
        let artifact = field(value, "artifact")?;
        only(artifact, &["component", "component_sha256"], "artifact")?;
        let component = PathBuf::from(string(artifact, "component")?);
        if !component.is_absolute() {
            return Err("spec: artifact.component must be an absolute path".into());
        }
        let component_sha256 = optional_string(artifact, "component_sha256")?;
        if component_sha256.as_deref().is_some_and(|d| !hex64(d)) {
            return Err("spec: artifact.component_sha256 must be a lowercase hex SHA-256".into());
        }

        let runtime_dir = match value.get("runtime") {
            None | Some(Value::Null) => None,
            Some(runtime) => {
                only(runtime, &["dir"], "runtime")?;
                let dir = PathBuf::from(string(runtime, "dir")?);
                if !dir.is_absolute() {
                    return Err("spec: runtime.dir must be an absolute path".into());
                }
                Some(dir)
            }
        };
        let identity = |name: &str| -> Result<Option<u32>, String> {
            match value.get(name) {
                None | Some(Value::Null) => Ok(None),
                Some(v) => v
                    .as_u64()
                    .and_then(id)
                    .map(Some)
                    .ok_or_else(|| format!("spec: {name} must be a non-root id")),
            }
        };
        let (uid, gid) = (identity("uid")?, identity("gid")?);
        if uid.is_some() != gid.is_some() {
            return Err("spec: uid and gid go together".into());
        }
        let cpu = match value.get("cpu") {
            None | Some(Value::Null) => None,
            Some(v) => Some(
                v.as_u64()
                    .filter(|c| *c < libc::CPU_SETSIZE as u64)
                    .ok_or("spec: cpu must be a CPU number")? as usize,
            ),
        };
        let share_core = match value.get("share_core") {
            None | Some(Value::Null) => false,
            Some(v) => v
                .as_bool()
                .ok_or("spec: share_core must be true or false")?,
        };

        let guest = fenders_node::core::validate_spec(field(value, "guest")?)
            .map_err(|e| format!("spec: guest: {}", e.message))?;
        for unsupported in ["network_start_blocked", "network_deadline_ns"] {
            if guest
                .get(unsupported)
                .is_some_and(|v| !v.is_null() && v != false && v != "")
            {
                return Err(format!(
                    "spec: guest.{unsupported} is not supported by fenders-shim"
                ));
            }
        }
        if !matches!(guest["mode"].as_str(), Some("command" | "http")) {
            return Err("spec: guest.mode must be command or http".into());
        }

        Ok(Self {
            component,
            component_sha256,
            runtime_dir,
            uid,
            gid,
            cpu,
            share_core,
            guest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn spec() -> Value {
        json!({
            "protocol": 1,
            "run": {"execution": "exec-1", "generation": 3, "trace_id": "abc-123"},
            "channel": {
                "endpoint": "https://10.0.0.1:7443/internal/run/",
                "credential": "secret-credential",
                "trust": {"ca_pem": "-----BEGIN CERTIFICATE-----"}
            },
            "artifact": {"component": "/var/cache/component.cwasm"},
            "uid": 61000, "gid": 61000,
            "guest": {
                "artifact": "a".repeat(64),
                "mode": "command",
                "cpu_percent": 100,
                "guest_memory_mib": 64,
                "host_memory_mib": 96,
                "wasm_memory_mib": 24,
                "lifetime_seconds": 60,
                "host_origin": "http://api.runtara.internal",
                "env": {}
            }
        })
    }

    #[test]
    fn a_vm_has_a_core_of_its_own_unless_told_to_share() {
        let parse = |value: &Value| Spec::parse(&serde_json::to_vec(value).unwrap());
        assert!(!parse(&spec()).unwrap().machine.share_core);
        let mut shared = spec();
        shared["share_core"] = json!(true);
        assert!(parse(&shared).unwrap().machine.share_core);
        shared["share_core"] = json!("yes");
        assert!(parse(&shared).is_err());
    }

    #[test]
    fn parses_a_spec_and_keeps_the_endpoint_prefix() {
        let parsed = Spec::parse(&serde_json::to_vec(&spec()).unwrap()).unwrap();
        assert_eq!(parsed.run.execution, "exec-1");
        assert_eq!(parsed.run.generation, 3);
        assert_eq!(parsed.channel.endpoint.path(), "/internal/run");
        assert_eq!(parsed.channel.credential, "secret-credential");
        assert_eq!(parsed.machine.uid, Some(61000));
        assert_eq!(
            parsed.machine.guest["host_origin"],
            "http://api.runtara.internal:80"
        );
    }

    #[test]
    fn errors_never_echo_the_credential() {
        let mut bad = spec();
        bad["channel"]["endpoint"] = json!("http://plain");
        let error = Spec::parse(&serde_json::to_vec(&bad).unwrap())
            .err()
            .unwrap();
        assert!(!error.contains("secret-credential"), "{error}");
        let mut bad = spec();
        bad["channel"]["credential"] = json!("has space secret-credential");
        let error = Spec::parse(&serde_json::to_vec(&bad).unwrap())
            .err()
            .unwrap();
        assert!(!error.contains("secret-credential"), "{error}");
    }

    #[test]
    fn a_warm_spec_is_the_machine_alone_and_a_claim_the_run_alone() {
        let full = spec();
        let mut warm = full.clone();
        for run_part in ["run", "channel"] {
            warm.as_object_mut().unwrap().remove(run_part);
        }
        warm["warm"] = json!(true);
        let machine = Spec::parse_warm(&serde_json::to_vec(&warm).unwrap()).unwrap();
        assert_eq!(machine.uid, Some(61000));
        let claim = json!({"run": full["run"], "channel": full["channel"],
            "launcher": {"id": "run-1", "key": "key-1", "uid": 0}});
        let spec = Spec::claim(machine, &serde_json::to_vec(&claim).unwrap()).unwrap();
        assert_eq!(spec.run.execution, "exec-1");
        assert_eq!(spec.launcher.unwrap().id, "run-1");
        assert_eq!(spec.machine.guest["lifetime_seconds"], 60);

        // A warm spec says so, and carries no run; a claim carries no machine.
        let mut unmarked = warm.clone();
        unmarked.as_object_mut().unwrap().remove("warm");
        assert!(Spec::parse_warm(&serde_json::to_vec(&unmarked).unwrap()).is_err());
        assert!(Spec::parse_warm(&serde_json::to_vec(&full).unwrap()).is_err());
        let machine = Spec::parse_warm(&serde_json::to_vec(&warm).unwrap()).unwrap();
        let mut overreach = claim.clone();
        overreach["uid"] = json!(0);
        let error = Spec::claim(machine, &serde_json::to_vec(&overreach).unwrap())
            .err()
            .unwrap();
        assert!(!error.contains("secret-credential"), "{error}");
    }

    /// Outbound access is the launch's own policy: addresses, origins and the
    /// addresses a public origin was resolved to, with no lease to renew.
    #[test]
    fn takes_static_outbound_policy_and_refuses_a_lease() {
        let mut launch = spec();
        for (name, value) in [
            ("tcp_allow", json!(["10.50.0.2:5432", "93.184.216.34:443"])),
            ("http_allow", json!(["https://example.com:443"])),
            (
                "http_public_targets",
                json!("https://example.com:443=93.184.216.34"),
            ),
            ("http_runtime_digest", json!("b".repeat(64))),
        ] {
            launch["guest"][name] = value;
        }
        let parsed = Spec::parse(&serde_json::to_vec(&launch).unwrap()).unwrap();
        assert_eq!(
            parsed.machine.guest["http_public_targets"],
            "https://example.com:443=93.184.216.34"
        );
        let environment = fenders_node::guest_env::encode(&parsed.machine.guest).unwrap();
        let records = environment.split(|b| *b == 0).collect::<Vec<_>>();
        // The address of a public origin is not also a raw socket permission.
        assert!(records.contains(&b"FENDERS_SOCKET_ALLOW=10.50.0.2:5432".as_slice()));
        for (name, value) in [
            ("network_deadline_ns", json!(0)),
            ("network_start_blocked", json!(true)),
        ] {
            let mut leased = launch.clone();
            leased["guest"]["network_deadline_ns"] = json!(0);
            leased["guest"][name] = value;
            assert!(
                Spec::parse(&serde_json::to_vec(&leased).unwrap()).is_err(),
                "{name}"
            );
        }
    }

    /// The outbound byte limit is asked for in the guest configuration.
    #[test]
    fn takes_the_outbound_byte_limit() {
        let mut launch = spec();
        launch["guest"]["egress_budget"] = json!(true);
        let parsed = Spec::parse(&serde_json::to_vec(&launch).unwrap()).unwrap();
        assert!(crate::budget::wanted(&parsed.machine.guest));
        assert!(!crate::budget::wanted(
            &Spec::parse(&serde_json::to_vec(&spec()).unwrap())
                .unwrap()
                .machine
                .guest
        ));
    }

    #[test]
    fn an_http_run_is_accepted_but_not_started_warm() {
        let mut http = spec();
        http["guest"]["mode"] = json!("http");
        let parsed = Spec::parse(&serde_json::to_vec(&http).unwrap()).unwrap();
        assert_eq!(parsed.machine.guest["mode"], "http");
        for run_part in ["run", "channel"] {
            http.as_object_mut().unwrap().remove(run_part);
        }
        http["warm"] = json!(true);
        assert!(Spec::parse_warm(&serde_json::to_vec(&http).unwrap()).is_err());
    }

    #[test]
    fn refuses_root_unknown_fields_and_host_side_network_gates() {
        for (path, value) in [
            ("/uid", json!(0)),
            ("/surprise", json!(1)),
            ("/channel/endpoint", json!("https://user:pw@host/")),
            ("/guest/egress_budget", json!(false)),
            ("/guest/mode", json!("other")),
        ] {
            let mut bad = spec();
            let (parent, name) = path.rsplit_once('/').unwrap();
            bad.pointer_mut(if parent.is_empty() { "" } else { parent })
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(name.to_owned(), value);
            assert!(
                Spec::parse(&serde_json::to_vec(&bad).unwrap()).is_err(),
                "{path}"
            );
        }
    }
}
