#!/usr/bin/env bash
# Runs one command end to end on this host: the built control plane (TLS, with
# its run channel), a real fenders-node started as root, a shim and a KVM
# guest. Shows that an assignment names its run channel, the node starts the
# run, the shim reaches the channel and the run's exit is recorded.
#
#   bash scripts/verify_run_channel_live.sh [OUTPUT_DIR]
#
# Its node gives runs uids from 620000, a base of its own: two nodes on one
# host may not share one, and scripts/local_env.sh keeps the default.
# Needs: Linux x86-64 with /dev/kvm, cgroup v2, passwordless sudo, Docker (for a
# disposable PostgreSQL 17), curl, jq, and `scripts/build_node.sh` already run.
# It creates OUTPUT_DIR, /var/lib/fenders-run-channel-live (a copy of the node
# bundle and the node's state), one cgroup and one container; all but
# OUTPUT_DIR's logs and result.json are removed on exit.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$repo/run/run-channel-live-$(date +%Y%m%d-%H%M%S)}
build=$repo/build/node
bin=$repo/target/release
for file in "$build/fenders-node" "$build/fenders-shim" "$build/launch" "$build/runtime.elf" \
  "$build/example-command.wasm" "$bin/fenders-control-plane" "$bin/fenders-pki"; do
  [[ -f $file ]] || { echo "missing $file: run scripts/build_node.sh" >&2; exit 2; }
done
[[ -c /dev/kvm ]] && sudo -n true
mkdir -p "$out"
out=$(cd "$out" && pwd)
pg=fenders-run-channel-live
cgroup=/sys/fs/cgroup/fenders-run-channel-live
# The compiler and the runs drop root's privileges, so the bundle and the
# node's state must be reachable without them: not under a private home.
stage=/var/lib/fenders-run-channel-live
base=19290
manage=https://127.0.0.1:$base
control_pid='' node_pid=''
cleanup() {
  [[ -n $node_pid ]] && sudo kill "$node_pid" 2>/dev/null || true
  [[ -n $control_pid ]] && kill "$control_pid" 2>/dev/null || true
  sleep 1
  if [[ -d $cgroup ]]; then
    echo 1 | sudo tee "$cgroup/cgroup.kill" >/dev/null 2>&1 || true
    sleep 1
    sudo find "$cgroup" -depth -type d -exec rmdir {} + 2>/dev/null || true
  fi
  docker rm -f "$pg" >/dev/null 2>&1 || true
  sudo rm -rf "$stage"
  sudo chown -R "$(id -u):$(id -g)" "$out" 2>/dev/null || true
}
trap cleanup EXIT

docker rm -f "$pg" >/dev/null 2>&1 || true
docker run -d --name "$pg" -p 127.0.0.1:$((base + 9)):5432 -e POSTGRES_PASSWORD=live \
  -e POSTGRES_DB=fenders --tmpfs /var/lib/postgresql/data postgres:17-alpine >/dev/null
# Asked over TCP: on a new data directory the image first runs a server
# that listens on its socket alone, says it is ready there, and restarts.
until docker exec "$pg" pg_isready -q -h 127.0.0.1 -U postgres; do sleep 1; done
sleep 1

"$bin/fenders-pki" --output "$out/pki" --identity control=127.0.0.1 --identity node=127.0.0.1 \
  > "$out/pins.json"
FENDERS_DATABASE_URL=postgresql://postgres:live@127.0.0.1:$((base + 9))/fenders \
  "$bin/fenders-control-plane" --state "$out/control" --host 127.0.0.1 \
  --port $base --internal-port $((base + 1)) --gateway-port $((base + 2)) \
  --run-channel-port $((base + 3)) --run-channel-endpoint "https://127.0.0.1:$((base + 3))" \
  --ca "$out/pki/ca.pem" --cert "$out/pki/control.pem" --key "$out/pki/control.key" \
  > "$out/control.log" 2>&1 &
control_pid=$!
until [[ -s $out/control/operator.token ]] && curl -s --cacert "$out/pki/ca.pem" -o /dev/null "$manage/"; do
  kill -0 "$control_pid" || { cat "$out/control.log" >&2; exit 1; }
  sleep 1
done
token=$(cat "$out/control/operator.token")
api() { # METHOD PATH [JSON]
  curl -sS --fail-with-body --cacert "$out/pki/ca.pem" -X "$1" -H "Authorization: Bearer $token" \
    -H "Idempotency-Key: live-$RANDOM-$RANDOM-$RANDOM" -H 'Content-Type: application/json' \
    ${3:+-d "$3"} "$manage/v1$2"
}

tenant=$(api POST /tenants '{"name":"live","allowance":{"cpu_percent":400,"memory_mib":2048,"storage_bytes":1073741824,"instances":4,"transfer_bytes":1073741824}}' | jq -er .id)
project=$(api POST "/tenants/$tenant/projects" '{"name":"main"}' | jq -er .id)
scope=/tenants/$tenant/projects/$project
node_port=$((base + 4))
api POST /nodes "$(jq -n --arg pin "$(jq -er .node "$out/pins.json")" --arg endpoint "https://127.0.0.1:$node_port" \
  '{name:"live-node",cert_sha256:$pin,endpoint:$endpoint,backend:"wasm",architecture:"x86_64",
    runtime:"wasmtime-50.0.0-fenders-v1",cpu_percent:200,memory_mib:1024,instances:4}')" > "$out/node.json"

sudo rm -rf "$stage"
sudo install -d -m 0755 "$stage" "$stage/build"
sudo cp "$build"/{fenders-node,fenders-shim,launch,runtime.elf,compile} "$stage/build/"
sudo chmod -R a+rX "$stage/build"
sudo "$stage/build/fenders-node" --state "$stage/state" --build "$stage/build" --cgroup-root "$cgroup" \
  --control "https://127.0.0.1:$((base + 1))" --control-pin "$(jq -er .control "$out/pins.json")" \
  --ca "$out/pki/ca.pem" --cert "$out/pki/node.pem" --key "$out/pki/node.key" \
  --cpu-percent 200 --memory-mib 1024 --max-instances 4 --port "$node_port" \
  --local-destinations --nested-virtualization \
  --run-uid-base 620000 \
  > /dev/null 2> "$out/node.log" &
node_pid=$!

artifact=$(curl -sS --fail-with-body --cacert "$out/pki/ca.pem" -X POST -H "Authorization: Bearer $token" \
  -H "Idempotency-Key: live-artifact-$RANDOM" -H 'Content-Type: application/wasm' \
  --data-binary @"$build/example-command.wasm" "$manage/v1$scope/artifacts" | jq -er .id)
# The node inspects the component before it can be run.
for _ in $(seq 60); do
  state=$(api GET "$scope/artifacts/$artifact/inspection" | jq -r '.state // empty') || state=''
  [[ $state == valid ]] && break
  [[ $state == invalid ]] && { echo "component rejected" >&2; exit 1; }
  sleep 1
done
[[ $state == valid ]] || {
  echo "inspection did not finish (state: $state)" >&2
  api GET "$scope/artifacts/$artifact/inspection" >&2 || true
  api GET /nodes >&2 || true
  tail -20 "$out/node.log" >&2
  exit 1
}

# The customer path: deploy an app with a manual trigger (nothing is invoked),
# then run it on request.
api POST "$scope/apps/deploy" "$(jq -n --arg a "$artifact" \
  '{name:"live-app",artifact_id:$a,triggers:{http:false,manual:true}}')" > "$out/app-deploy.json"
app=$(jq -er '.app.id // .app_id // .resource_id // .id' "$out/app-deploy.json")
for _ in $(seq 60); do
  api GET "$scope/apps/$app" > "$out/app.json"
  [[ $(jq -r .state "$out/app.json") == ready ]] && break
  sleep 1
done
# Twice: each run is a VM of its own, and each posts its own outcome.
for n in first second; do
  api POST "$scope/apps/$app/runs" '{}' > "$out/app-run-request.json"
  run=$(jq -er '.run.id // .run_id // .resource_id // .id' "$out/app-run-request.json")
  for _ in $(seq 60); do
    api GET "$scope/apps/$app/runs/$run" > "$out/app-run.json"
    run_state=$(jq -r .state "$out/app-run.json")
    case $run_state in succeeded|failed|cancelled) break ;; esac
    sleep 1
  done
  [[ $n == first ]] && { state=$run_state; exit_code=$(jq -r '.exit_code // empty' "$out/app-run.json"); }
done

jq -n --arg state "$state" --arg exit_code "$exit_code" --arg run_state "$run_state" \
  --slurpfile run "$out/app-run.json" \
  --arg started "$(grep -c 'agent: run started' "$out/node.log" || true)" \
  --arg posted "$(grep -c 'outcome="host"' "$out/node.log" || true)" \
  --arg refused "$(grep -c 'run refused' "$out/node.log" || true)" \
  '{passed: ($state == "succeeded" and $exit_code == "0" and $run_state == "succeeded"
      and ($posted|tonumber) == 2 and ($refused|tonumber) == 0),
    first_run: {state: $state, exit_code: $exit_code},
    app_run: {state: $run_state, exit_code: $run[0].exit_code, source: $run[0].source},
    node: {runs_started: ($started|tonumber), outcomes_posted_to_run_channel: ($posted|tonumber),
      runs_refused: ($refused|tonumber)}}' \
  | tee "$out/result.json"
grep -E 'run (started|ended|refused)' "$out/node.log" | tail -8 || true
jq -e .passed "$out/result.json" >/dev/null
