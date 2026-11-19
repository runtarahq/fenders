//! What an outcome means, said once for whoever reads it: a code to branch
//! on, a summary and a detail in words. Derived from the control plane's own
//! reason codes, never from what a worker said.
//!
//! It says what happened and what will or will not happen next. It does
//! not say where to click or whom to call: the product Fenders is built
//! into has its own screens and its own support, and says those itself.
use serde_json::{Value, json};
pub(crate) fn decorate(value: &mut Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    if object.get("source").and_then(Value::as_str) == Some("http") {
        if object.get("state").and_then(Value::as_str) == Some("unknown") {
            object.insert("diagnostic".into(),json!({"code":"http-outcome-unknown","summary":"The HTTP response could not be confirmed.","detail":"The request may have reached the app. Fenders does not retry it automatically."}));
        }
        return;
    }
    let placement = object.get("placement");
    let reason = placement
        .and_then(|v| v["reason"].as_str())
        .or_else(|| object.get("reason").and_then(Value::as_str));
    let state = object
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let reason = reason.or_else(|| {
        (state == "failed"
            && object
                .get("exit_code")
                .and_then(Value::as_i64)
                .is_some_and(|code| code != 0))
        .then_some("command-exited-with-error")
    });
    if let Some(mut diagnostic) = diagnostic(reason, state) {
        if let Some(observed) = placement.and_then(|v| v.get("observed_at")) {
            diagnostic["observed_at"] = observed.clone();
        }
        object.insert("diagnostic".into(), diagnostic);
    }
}
pub(crate) fn app(value: &mut Value) {
    for name in ["http", "active_release", "target_release", "latest_run"] {
        if let Some(item) = value.get_mut(name) {
            decorate(item);
        }
    }
}
const UNRECOGNIZED: &str = "No recognized diagnostic is available for this outcome.";
fn diagnostic(reason: Option<&str>, state: &str) -> Option<Value> {
    let code = match reason {
        Some(code) => code,
        None if state == "unknown" => "command-outcome-unknown",
        None if matches!(state, "failed" | "unavailable") => "unclassified",
        None => return None,
    };
    let (summary, detail): (&str, &str) = match code {
        "placement-no-worker" => (
            "Waiting for an available compatible worker.",
            "At the last placement check, no available worker could run this component. Fenders will check again. Workspace allowance does not guarantee an available worker.",
        ),
        "placement-confinement" => (
            "Waiting for a worker with verified isolation.",
            "Fenders is waiting for a worker that has passed the required isolation checks.",
        ),
        "placement-private-network" => (
            "Waiting for a worker with private network support.",
            "A worker that can enforce this app's private connections is not currently available. Access remains limited to saved connections.",
        ),
        "placement-public-https" => (
            "Waiting for a worker with approved HTTPS support.",
            "A worker that can securely reach this app's HTTPS destinations is not currently available. Access remains limited to saved destinations.",
        ),
        "placement-egress-budget" => (
            "Waiting for verified outbound allowance enforcement.",
            "Fenders is waiting for a worker that can enforce the required outbound allowance.",
        ),
        "placement-size" => (
            "No eligible worker supports this app size.",
            "At the last check, workers that passed the runtime and security checks lacked the configured CPU, memory or instance capacity for this app. Review its size; workspace allowance alone cannot make it fit.",
        ),
        "placement-capacity" => (
            "Compatible worker capacity is currently occupied.",
            "At the last check, workers that support this app lacked enough unreserved CPU, memory or execution slots. Fenders will check again within the existing startup or admission deadline. Increasing workspace allowance alone does not free worker capacity.",
        ),
        "placement-public-policy" => (
            "Public HTTPS placement is awaiting platform configuration.",
            "HTTPS access configuration needs attention from Fenders before this app can be placed. Access remains restricted to saved destinations.",
        ),
        "capacity-deadline" => (
            "The scheduled run could not obtain a worker before its deadline.",
            "The occurrence was skipped and will not be replayed automatically. Review recent runs and current capacity before choosing an explicit run.",
        ),
        "waiting-for-capacity" => (
            "Waiting for an eligible execution slot.",
            "Fenders checks for eligible capacity until the startup or admission deadline. Workspace allowance does not guarantee an immediately available slot.",
        ),
        "allowance-exhausted" => (
            "Workspace allowance is currently exhausted.",
            "Review reservations and usage. Stop unneeded workloads or ask the operator to review the allowance. Pending work is still subject to its admission or startup deadline.",
        ),
        "starting-http" | "waking-http" => (
            "HTTP is starting.",
            "The endpoint becomes available only after a fresh running observation. Refresh to check progress; submitting another deployment is unnecessary.",
        ),
        "local-storage" => (
            "The worker could not admit this execution because storage was constrained.",
            "This request did not start the component. After capacity is restored, explicitly run the command again or activate the intended HTTP version. Fenders will not replay this command automatically.",
        ),
        "draining-http" | "idle-drain" => (
            "Waiting for HTTP work to drain and stop.",
            "Existing work and compute reservations remain until shutdown is confirmed. An idle app can wake again on its next request.",
        ),
        "restarting-http" => (
            "HTTP is waiting for an automatic restart.",
            "Inspect the previous execution's output. Repeated failures eventually block automatic restart; command runs are never retried by this HTTP policy.",
        ),
        "http-startup-failed" => (
            "The HTTP execution stopped before becoming ready.",
            "Inspect startup output and configuration. After correcting the cause, explicitly activate the intended version again. This request will not silently repeat a failed rollout.",
        ),
        "http-readiness-timeout" => (
            "HTTP did not become ready before its deadline.",
            "Inspect startup events and output for capacity, worker or application failures. Correct the cause before explicitly activating a version again; unconfirmed workers retain their reservation.",
        ),
        "http-restart-limit" => (
            "Repeated HTTP failures have blocked automatic restart.",
            "Inspect output and correct the cause before explicitly activating a version again. Fenders continues to require confirmed shutdown before releasing compute.",
        ),
        "previous-worker-not-stopped" => (
            "The previous execution has not confirmed shutdown.",
            "Replacement is blocked and uncertain compute remains reserved. Inspect lifecycle events if it does not settle. Repeated submissions cannot safely bypass this barrier.",
        ),
        "worker-unavailable" | "worker-unreachable" => (
            "The worker is not currently eligible to serve HTTP.",
            "Traffic remains unavailable until a fresh, trusted running observation is received. Reservations are retained while execution is uncertain. Inspect events if this persists.",
        ),
        "worker-lost" if state != "unknown" => (
            "Worker contact was lost after a command result was recorded.",
            "Review the recorded command state, exit status and output before deciding what to do next. Fenders will not replay the command automatically.",
        ),
        "outbound-allowance-denied" => (
            "An outbound write exceeded this execution's available transfer allowance.",
            "The host refused at least one write during this failed command. A whole write may exceed the remaining allowance even when some bytes are available. Review workspace usage and ask the operator to review the allowance. After resolving it, check for earlier external effects before explicitly running again. Increasing allowance does not replay this command.",
        ),
        "outbound-grant-expired" => (
            "An outbound write was refused because its transfer authorization expired.",
            "The host could not admit at least one write during this failed command. This is not proof that workspace allowance was exhausted. Review output and external effects before choosing another run; this command is not replayed automatically.",
        ),
        "outbound-accounting-unavailable" => (
            "An outbound write was refused because safe transfer accounting was unavailable.",
            "The host refused at least one write during this failed command. This does not prove workspace allowance was exhausted. Check output and external effects before explicitly running again; this command is not replayed automatically.",
        ),
        "command-exited-with-error" => (
            "The command returned a non-zero exit status.",
            "Inspect command output and configuration before deciding whether to run it again. A failed command may already have produced external effects.",
        ),
        "worker-lost" | "command-outcome-unknown" => (
            "The command outcome could not be confirmed.",
            "Inspect its output and any external effects before deciding whether to run it again. Fenders will not replay it automatically; an uncertain reservation may still be held.",
        ),
        "configuration-unavailable" => (
            "A required configuration reference is unavailable.",
            "Review configuration, secret references and service connections. Correct missing references before explicitly activating a version again.",
        ),
        "dependency-unavailable" => (
            "A required dependency could not be used.",
            "Review service health, selected connections and configuration references. A skipped command is not automatically replayed when the dependency recovers.",
        ),
        "incompatible-http-entry-point" => (
            "This component does not provide a compatible HTTP entry point.",
            "Choose a component that supports HTTP or disable the HTTP trigger. Changing a trigger cannot add an export to a component.",
        ),
        "http-generation-limit" => (
            "This app requires platform recovery before HTTP can restart.",
            "The operator recovers it, by the app and request identifiers. Further retries cannot reset the execution generation safely.",
        ),
        "restored-control-plane" | "restored-control-plane-requires-reconciliation" => (
            "Work is fenced after a control-plane restore.",
            "The operator must recover it. Old executions, access and uncertain outcomes must be reconciled before new work is admitted.",
        ),
        "superseded" => (
            "A newer release replaced this pending release.",
            "Review versions to find the current target. This historical release will not resume automatically.",
        ),
        "connection-removed" => (
            "Cancelled after a connection was removed.",
            "A connection this run was started with was removed from the app. A run's connections are fixed when it starts, so Fenders enforces the removal by stopping the runs that hold it. This command will not be replayed automatically. Review retained output before choosing another run; cancellation does not undo external effects.",
        ),
        "app-stopped" => (
            "The app was stopped.",
            "Starting restores the saved triggers but does not invoke a command. Review current app state before requesting further work.",
        ),
        "command-busy" => (
            "Another command was active or had an uncertain reservation.",
            "Only one command can be admitted at a time. This skipped occurrence is not replayed automatically. Review the existing run's outcome first.",
        ),
        "missed-deadline" => (
            "The scheduled occurrence missed its admission window.",
            "Late occurrences are recorded as skipped rather than replayed in a burst. Review schedule settings and recent runs before requesting an explicit test run.",
        ),
        "release-unavailable" => (
            "No compatible ready release could accept this command.",
            "Review the target release and its readiness. This skipped occurrence will not run automatically after the release recovers.",
        ),
        "trigger-disabled-or-changed" | "trigger-changed" => (
            "The schedule was disabled or changed before execution.",
            "This occurrence was cancelled or skipped under its original trigger revision. Review the current schedule; old occurrences are not replayed.",
        ),
        "timezone-database-changed" => (
            "The schedule needs review after a timezone database change.",
            "Review and save the schedule with the current timezone rules before relying on future occurrences.",
        ),
        _ => (
            UNRECOGNIZED,
            "Inspect lifecycle events and retained output. If the cause is unclear, the operator can trace it by the app or request identifier. Do not repeat a command whose external effects are uncertain.",
        ),
    };
    // A reason this does not know is not echoed: it may be a worker's words.
    let code = if summary == UNRECOGNIZED {
        "unrecognized"
    } else {
        code
    };
    Some(json!({"code":code,"summary":summary,"detail":detail}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostic_fallback_never_echoes_arbitrary_worker_messages() {
        let value = diagnostic(Some("private-token<script>\u{202e}"), "failed").unwrap();
        assert!(!value.to_string().contains("private-token"));
        assert_eq!(
            value,
            diagnostic(Some(&"a".repeat(10000)), "failed").unwrap()
        );
        assert!(value.to_string().len() < 1024);
        assert_eq!(value["code"], "unrecognized");
        assert!(diagnostic(None, "ready").is_none());
        // A reason it knows is the code; and no diagnostic says where to
        // click or whom to call.
        let known = diagnostic(Some("placement-no-worker"), "queued").unwrap();
        assert_eq!(known["code"], "placement-no-worker");
        for reason in [
            "placement-no-worker",
            "command-exited-with-error",
            "trigger-changed",
            "anything else",
        ] {
            let said = diagnostic(Some(reason), "failed").unwrap();
            let names: Vec<_> = said.as_object().unwrap().keys().cloned().collect();
            assert_eq!(names, ["code", "detail", "summary"], "{reason}");
            assert!(
                !said.to_string().to_lowercase().contains("support"),
                "{said}"
            );
        }
        assert!(
            diagnostic(None, "unknown").unwrap()["detail"]
                .as_str()
                .unwrap()
                .contains("not replay")
        );
    }
}
