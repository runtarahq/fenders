#!/usr/bin/env bash
# A shim asked to stop once its run is over stops, on this host, with a real
# KVM guest and no node: one command run under fenders-shim against
# fenders-shim-stub, with a launcher's link so that the shim holds the run's
# end for a launcher that never collects it.
#
#   bash scripts/verify_shim_stop_live.sh [OUTPUT_DIR]
#
# Passes when
#  - the run ends and the shim is still there a few seconds later, holding
#    its end for its launcher (it would for an hour);
#  - sent SIGTERM then, the shim is gone within two seconds, and its cgroup
#    is empty.
# Needs: Linux x86-64 with /dev/kvm, cgroup v2, passwordless sudo,
# systemd-run, jq, python3, `scripts/build_node.sh` already run and
# `cargo build -p fenders-shim --bin fenders-shim-stub`.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$repo/run/shim-stop-live-$(date +%Y%m%d-%H%M%S)}
build=$repo/build/node
stub_bin=$repo/target/debug/fenders-shim-stub
for file in "$build/fenders-shim" "$build/launch" "$build/runtime.elf" "$build/compile" \
  "$build/example-command.wasm" "$stub_bin"; do
  [[ -f $file ]] || { echo "missing $file" >&2; exit 2; }
done
[[ -c /dev/kvm ]] && sudo -n true
mkdir -p "$out"
out=$(cd "$out" && pwd)
# The run drops root's privileges: the bundle must be reachable without them.
stage=/var/lib/fenders-shim-stop-live
unit=fenders-shim-stop-live-$$
run_id=$(printf 'shim-stop-live-%s' "$$" | sha256sum | cut -c1-32)
stub=''
cleanup() {
  sudo systemctl stop "$unit.scope" 2>/dev/null || true
  [[ -n $stub ]] && kill "$stub" 2>/dev/null || true
  sudo rm -rf "$stage"
}
trap cleanup EXIT
sudo rm -rf "$stage"
sudo install -d -m 0755 "$stage"
sudo cp "$build"/{fenders-shim,launch,runtime.elf} "$stage/"
"$build/compile" "$build/example-command.wasm" "$out/component.cwasm"
sudo cp "$out/component.cwasm" "$stage/"
sudo chmod -R a+rX "$stage"
"$stub_bin" --dir "$out" > "$out/calls.jsonl" 2>/dev/null &
stub=$!
for _ in $(seq 50); do [[ -s $out/channel.json ]] && break; sleep 0.1; done
jq -n --slurpfile channel "$out/channel.json" --arg component "$stage/component.cwasm" \
  --arg artifact "$(sha256sum "$build/example-command.wasm" | cut -d' ' -f1)" --arg id "$run_id" '{
    protocol: 1,
    run: {execution: "shim-stop-live", generation: 1},
    channel: $channel[0],
    launcher: {id: $id, key: "shim-stop-live", uid: 0},
    artifact: {component: $component},
    uid: 61000, gid: 61000,
    guest: {artifact: $artifact, mode: "command", cpu_percent: 100,
            guest_memory_mib: 566, host_memory_mib: 598, wasm_memory_mib: 256,
            lifetime_seconds: 60, instances: 1000, tables: 1000, memories: 1000,
            table_elements: 1000000, env: {}}
  }' > "$out/spec.json"
sudo systemd-run --scope --quiet -p Delegate=yes --unit="$unit" \
  "$stage/fenders-shim" < "$out/spec.json" > "$out/shim.out" 2> "$out/shim.log" &
# The shim's own status, asked as its launcher would over its link.
status() {
  sudo python3 - "$run_id" <<'PY' 2>/dev/null || echo '{}'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(3)
s.connect("\0fenders/run/" + sys.argv[1])
s.sendall(b"status\n")
data = b""
while True:
    piece = s.recv(65536)
    if not piece:
        break
    data += piece
print(data.decode().strip())
PY
}
state=''
for _ in $(seq 100); do
  state=$(status | jq -r '.state // empty')
  [[ $state == exited || $state == failed ]] && break
  sleep 0.3
done
status > "$out/ended.json"
# Still there some seconds on: it holds the run's end for its launcher.
sleep 4
shim_pid=$(sudo cat "/sys/fs/cgroup/system.slice/$unit.scope/shim/cgroup.procs" 2>/dev/null | head -1)
held=false
[[ -n $shim_pid ]] && sudo kill -0 "$shim_pid" 2>/dev/null && held=true
stopped_in=null
if [[ $held == true ]]; then
  started=$(date +%s.%N)
  sudo kill -TERM "$shim_pid"
  for _ in $(seq 40); do
    sudo kill -0 "$shim_pid" 2>/dev/null || break
    sleep 0.05
  done
  if ! sudo kill -0 "$shim_pid" 2>/dev/null; then
    stopped_in=$(printf '%.3f' "$(echo "$(date +%s.%N) - $started" | bc)")
  fi
fi
# Its scope goes with its last process: no such cgroup is no process left.
left=$( (sudo sh -c "cat /sys/fs/cgroup/system.slice/$unit.scope/cgroup.procs /sys/fs/cgroup/system.slice/$unit.scope/*/cgroup.procs" 2>/dev/null || true) | wc -l)
jq -n --arg state "$state" --argjson held "$held" --argjson stopped_in "$stopped_in" \
  --argjson left "$left" --slurpfile ended "$out/ended.json" '
  {run: {state: $state, exit_code: $ended[0].exit_code},
   shim_held_the_end: $held, stopped_within_seconds: $stopped_in, processes_left: $left}
  | .passed = (.run.state == "exited" and .shim_held_the_end
      and (.stopped_within_seconds != null and .stopped_within_seconds < 2)
      and .processes_left == 0)' | tee "$out/result.json"
jq -e .passed "$out/result.json" > /dev/null
