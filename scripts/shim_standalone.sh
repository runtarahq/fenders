#!/usr/bin/env bash
# Runs one compiled component under fenders-shim against fenders-shim-stub,
# with no node, fleet or Runtara: the standalone test of the run unit.
#
#   sudo scripts/shim_standalone.sh RUNTIME_DIR COMPONENT.cwasm ARTIFACT_SHA256 [UID]
#
# RUNTIME_DIR holds fenders-shim, launch and runtime.elf (root-owned, readable
# by UID); COMPONENT.cwasm was compiled for that runtime. The run gets its own
# transient scope (its cgroup), drops to UID (default 61000) and calls the
# stub over HTTPS. Prints the stub's call log and the shim's end report.
# With WARM=1 the shim starts warm (`fenders-shim warm`): the spec without its
# run first, then, a second later, the claim for the run.
# GUEST_ENV (a JSON object) is the guest's environment. OUTPUT (a JSON object,
# such as '{"redact_env":["TOKEN"]}') asks for the guest's output, which the
# stub then prints with its calls; STUB_ARGS are passed to the stub.
# GUEST_POLICY (a JSON object) is merged into the guest part of the spec: the
# launch's outbound policy (`tcp_allow`, `http_allow`, `http_public_targets`
# with `http_runtime_digest`), and `egress_budget` for the outbound byte limit,
# which the stub grants with STUB_ARGS='--allowance BYTES'.
# An HTTP app: GUEST_POLICY='{"mode":"http","lifetime_seconds":8}' with a
# component that exports an HTTP handler, and STUB_ARGS='--http JSON' with the
# requests to give it (an array of {"method","path","headers","body"}); the
# stub prints each answer, and the run ends at its lifetime.
# Needs root, KVM, cgroup v2, systemd-run and jq.
set -euo pipefail
runtime_dir=$1 component=$2 artifact=$3 uid=${4:-61000}
repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'kill "$stub" 2>/dev/null || true; rm -rf "$work"' EXIT
"$repo/target/debug/fenders-shim-stub" --dir "$work" ${STUB_ARGS:-} >"$work/calls.jsonl" 2>/dev/null &
stub=$!
for _ in $(seq 50); do [[ -s $work/channel.json ]] && break; sleep 0.1; done
jq -n --slurpfile channel "$work/channel.json" \
  --arg component "$component" --arg artifact "$artifact" --argjson uid "$uid" \
  --argjson env "${GUEST_ENV:-{\}}" --argjson output "${OUTPUT:-null}" \
  --argjson policy "${GUEST_POLICY:-{\}}" '{
    protocol: 1,
    run: {execution: "standalone-1", generation: 1, trace_id: "standalone-trace"},
    channel: $channel[0],
    artifact: {component: $component},
    uid: $uid, gid: $uid,
    guest: {artifact: $artifact, mode: "command", cpu_percent: 100,
            guest_memory_mib: 566, host_memory_mib: 598, wasm_memory_mib: 256,
            lifetime_seconds: 60, instances: 1000, tables: 1000, memories: 1000,
            table_elements: 1000000, host_origin: "http://api.runtara.internal", env: $env}
      + (if $output then {output: $output} else {} end) + $policy
  }' >"$work/spec.json"
status=0
if [[ ${WARM:-0} == 1 ]]; then
  jq -c 'del(.run, .channel) + {warm: true}' "$work/spec.json" >"$work/warm.json"
  jq -c '{run, channel}' "$work/spec.json" >"$work/claim.json"
  { cat "$work/warm.json"; sleep 1; cat "$work/claim.json"; } |
    systemd-run --scope --quiet -p Delegate=yes --unit="fenders-shim-standalone-$$" \
      "$runtime_dir/fenders-shim" warm || status=$?
else
  systemd-run --scope --quiet -p Delegate=yes --unit="fenders-shim-standalone-$$" \
    "$runtime_dir/fenders-shim" <"$work/spec.json" || status=$?
fi
echo "--- stub calls"
cat "$work/calls.jsonl"
exit "$status"
