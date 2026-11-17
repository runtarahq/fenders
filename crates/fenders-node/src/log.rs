//! The node's and its shims' logs: `tracing` events on standard error, one
//! line each, at the levels `RUST_LOG` names (`info` when unset), in one of
//! two formats ([`Format`]):
//!
//! - `text` (the default): `LEVEL target: message key=value ...`, without a
//!   timestamp, as a supervisor's journal stamps each line itself;
//! - `json`: one object per line, `{"timestamp", "level", "target",
//!   "message", ...}`, with the event's fields and those of the spans it is
//!   in at the top level beside them.
//!
//! Events about a run carry the fields that identify it, where they are
//! known: `run` (the node's id for the run, its shim's), `execution` (the
//! control plane's id for what the run serves, the assignment the agent
//! applies) and `tenant` (the compile scope the control plane names for the
//! assignment, its isolation unit; absent for one it names none).
//!
//! A shim logs in its node's format: the node passes `FENDERS_LOG_FORMAT`
//! and `RUST_LOG` to the shims it starts ([`child_env`]).
use serde_json::{Map, Value};
use std::fmt;
use std::sync::OnceLock;
use tracing::field::{Field, Visit};
use tracing_subscriber::{
    Layer,
    filter::{LevelFilter, Targets},
    fmt::{
        FmtContext, FormatEvent, FormatFields, FormattedFields,
        format::Writer,
        time::{FormatTime, SystemTime},
    },
    layer::SubscriberExt,
    registry::LookupSpan,
};

/// The environment variable a shim reads its node's log format from.
pub const FORMAT_VARIABLE: &str = "FENDERS_LOG_FORMAT";

/// How log lines are written.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// `LEVEL target: message key=value ...`.
    #[default]
    Text,
    /// One JSON object per line.
    Json,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Text => "text",
            Format::Json => "json",
        }
    }
    /// The format `FENDERS_LOG_FORMAT` names; text when unset or unknown.
    pub fn from_env() -> Self {
        match std::env::var(FORMAT_VARIABLE).as_deref() {
            Ok("json") => Format::Json,
            _ => Format::Text,
        }
    }
}

static INSTALLED: OnceLock<Format> = OnceLock::new();

/// The levels `RUST_LOG` names, in `tracing`'s target syntax
/// (`info`, `fenders_node=debug,warn`); `info` when unset or invalid.
fn filter(spec: Option<&str>) -> Targets {
    spec.and_then(|spec| spec.parse::<Targets>().ok())
        .unwrap_or_else(|| Targets::new().with_default(LevelFilter::INFO))
}

/// Installs the process's logger, once; later calls keep the first.
pub fn init(format: Format) {
    if INSTALLED.get().is_some() {
        return;
    }
    let rust_log = std::env::var("RUST_LOG").ok();
    let filter = filter(rust_log.as_deref());
    let installed = match format {
        Format::Text => tracing::subscriber::set_global_default(
            tracing_subscriber::registry().with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stderr)
                    .with_ansi(false)
                    .without_time()
                    .with_filter(filter),
            ),
        ),
        Format::Json => tracing::subscriber::set_global_default(
            tracing_subscriber::registry().with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stderr)
                    .fmt_fields(JsonFields)
                    .event_format(JsonLines)
                    .with_filter(filter),
            ),
        ),
    };
    if installed.is_ok() {
        let _ = INSTALLED.set(format);
    }
}

/// Whether [`init`] installed the logger: before it does, errors are
/// printed as they are.
pub fn installed() -> bool {
    INSTALLED.get().is_some()
}

/// What a shim the node starts needs to log as the node does.
pub fn child_env() -> Vec<(&'static str, String)> {
    let mut env = vec![(
        FORMAT_VARIABLE,
        INSTALLED
            .get()
            .copied()
            .unwrap_or_default()
            .as_str()
            .to_owned(),
    )];
    if let Ok(spec) = std::env::var("RUST_LOG") {
        env.push(("RUST_LOG", spec));
    }
    env
}

/// An event's or a span's fields as JSON values.
#[derive(Default)]
struct Fields(Map<String, Value>);

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_owned(), Value::from(value));
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().to_owned(), Value::from(value));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().to_owned(), Value::from(value));
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.0.insert(field.name().to_owned(), Value::from(value));
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().to_owned(), Value::from(value));
    }
    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.0
            .insert(field.name().to_owned(), Value::from(value.to_string()));
    }
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0
            .insert(field.name().to_owned(), Value::from(format!("{value:?}")));
    }
}

/// Keeps each span's fields as one JSON object, for [`JsonLines`].
struct JsonFields;

impl<'writer> FormatFields<'writer> for JsonFields {
    fn format_fields<R: tracing_subscriber::field::RecordFields>(
        &self,
        mut writer: Writer<'writer>,
        fields: R,
    ) -> fmt::Result {
        let mut visitor = Fields::default();
        fields.record(&mut visitor);
        write!(writer, "{}", Value::Object(visitor.0))
    }
    fn add_fields(
        &self,
        current: &'writer mut FormattedFields<Self>,
        fields: &tracing::span::Record<'_>,
    ) -> fmt::Result {
        let mut visitor = Fields(match serde_json::from_str(&current.fields) {
            Ok(Value::Object(map)) => map,
            _ => Map::new(),
        });
        fields.record(&mut visitor);
        current.fields = Value::Object(visitor.0).to_string();
        Ok(())
    }
}

/// One JSON object per event.
struct JsonLines;

impl<S> FormatEvent<S, JsonFields> for JsonLines
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, JsonFields>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> fmt::Result {
        let mut line = Map::new();
        let mut timestamp = String::new();
        SystemTime.format_time(&mut Writer::new(&mut timestamp))?;
        line.insert("timestamp".into(), Value::from(timestamp));
        let metadata = event.metadata();
        line.insert(
            "level".into(),
            Value::from(metadata.level().as_str().to_ascii_lowercase()),
        );
        line.insert("target".into(), Value::from(metadata.target()));
        // The spans' fields, outermost first, so an inner one's win.
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                if let Some(fields) = span.extensions().get::<FormattedFields<JsonFields>>()
                    && let Ok(Value::Object(fields)) = serde_json::from_str(&fields.fields)
                {
                    line.extend(fields);
                }
            }
        }
        let mut fields = Fields::default();
        event.record(&mut fields);
        line.extend(fields.0);
        writeln!(writer, "{}", Value::Object(line))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);
    impl io::Write for Buffer {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn json_lines(spec: &str, log: impl FnOnce()) -> Vec<Value> {
        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_writer(move || writer.clone())
                .fmt_fields(JsonFields)
                .event_format(JsonLines)
                .with_filter(filter(Some(spec))),
        );
        tracing::subscriber::with_default(subscriber, log);
        let text = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        text.lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn a_json_line_carries_its_level_target_message_and_the_runs_fields() {
        let lines = json_lines("info", || {
            let span = tracing::info_span!("run", run = "r1", execution = "e1");
            let _entered = span.enter();
            tracing::warn!(tenant = "t1", code = 3, "its shim did not answer");
            tracing::debug!("not at info");
        });
        assert_eq!(lines.len(), 1);
        let line = &lines[0];
        assert_eq!(line["level"], "warn");
        assert_eq!(line["target"], module_path!());
        assert_eq!(line["message"], "its shim did not answer");
        assert_eq!(line["run"], "r1");
        assert_eq!(line["execution"], "e1");
        assert_eq!(line["tenant"], "t1");
        assert_eq!(line["code"], 3);
        assert!(line["timestamp"].as_str().unwrap().ends_with('Z'));
    }

    #[test]
    fn rust_log_names_the_levels_and_an_invalid_one_means_info() {
        assert_eq!(
            json_lines("debug", || tracing::debug!("shown")).len(),
            1,
            "debug shown at debug"
        );
        assert_eq!(
            json_lines("warn", || tracing::info!("hidden")).len(),
            0,
            "info hidden at warn"
        );
        assert_eq!(
            json_lines("other_crate=debug,error", || tracing::warn!("hidden")).len(),
            0
        );
        assert_eq!(filter(Some("=bad=")).to_string(), "info");
        assert_eq!(filter(None).to_string(), "info");
    }
}
