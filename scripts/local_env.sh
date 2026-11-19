#!/usr/bin/env bash
# A whole Fenders on this machine: PostgreSQL 17 (a container), the control
# plane with TLS and its run channel, and this host as an enrolled node.
#
#   bash scripts/local_env.sh up       start (or restart) everything, keeping data
#   bash scripts/local_env.sh status   what is running, where, and the credential
#   bash scripts/local_env.sh run      upload the example command and run it once
#   bash scripts/local_env.sh down     stop everything, keeping data
#   bash scripts/local_env.sh destroy  stop everything and delete its data
#
# Needs Linux x86-64 with /dev/kvm, cgroup v2, passwordless sudo, Docker, curl
# and jq, and `make build-node` already run. State is in run/local (control
# plane, PKI, logs), /var/lib/fenders-local (the node's bundle and state, which
# the unprivileged compiler and runs must be able to reach) and the Docker
# volume fenders-local-pg.
# WARM_RUNS=N on `up` keeps N booted shims per artifact and guest configuration.
# Connections: an endpoint may be any public address or one on a Docker bridge
# (run/local/external-network.json), so a service in a local container can be
# one; HTTPS origins are resolved over DNS-over-TLS by the resolver named in
# run/local/public-egress.json (Cloudflare's unless LOCAL_DNS_ADDRESS and
# LOCAL_DNS_NAME say otherwise when the file is first written).
# The outbound byte limit: the node serves it (--egress-budget) and is
# registered as requiring it, with the launcher of the bundle it was started
# from as the approved one, so every run with a connection sends only what
# the workspace's transfer allowance grants. LOCAL_EGRESS_BUDGET=0 on `up`
# runs the node without it, and such runs then go unlimited.
# A product that wraps the control plane uses this script with its own
# binaries: LOCAL_BIN (the directory with fenders-control-plane and
# fenders-pki), LOCAL_BUILD (the node bundle), LOCAL_STATE (instead of
# run/local) and LOCAL_CONTROL_ARGS (further control-plane options).
# LOCAL_PG names the PostgreSQL container and its volume, for a second
# environment whose database is not the first's; with it, give LOCAL_STATE
# too, since a state directory and its database go together.
# For development only: one self-made CA, an operator token on disk,
# everything on 127.0.0.1.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
state=${LOCAL_STATE:-$repo/run/local}
build=${LOCAL_BUILD:-$repo/build/node}
bin=${LOCAL_BIN:-$repo/target/release}
stage=/var/lib/fenders-local
cgroup=/sys/fs/cgroup/fenders-local
pg=${LOCAL_PG:-fenders-local-pg}
manage_port=19090 internal_port=19091 gateway_port=19092 channel_port=19093 node_port=19094 pg_port=19099
manage=https://127.0.0.1:$manage_port

running() { [[ -s $1 ]] && sudo kill -0 "$(cat "$1")" 2>/dev/null; }
api() { # METHOD PATH [JSON]
  curl -sS --fail-with-body --cacert "$state/pki/ca.pem" -X "$1" \
    -H "Authorization: Bearer $(cat "$state/control/operator.token")" \
    -H "Idempotency-Key: local-$RANDOM-$RANDOM-$RANDOM" -H 'Content-Type: application/json' \
    ${3:+-d "$3"} "$manage/v1$2"
}

start_control() {
  if running "$state/control.pid"; then kill "$(cat "$state/control.pid")"; sleep 1; fi
  # What an app's connections may name. The shipped policy for a public
  # deployment (deploy/systemd/external-network-public.json) with Docker's
  # bridge range left out of what is denied.
  local special='["0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8","169.254.0.0/16","192.0.0.0/24","192.0.2.0/24","192.88.99.0/24","192.168.0.0/16","198.18.0.0/15","198.51.100.0/24","203.0.113.0/24","224.0.0.0/4","240.0.0.0/4"]'
  [[ -f $state/external-network.json ]] || jq -n --argjson denied "$special" \
    '{allowed_cidrs:["0.0.0.0/0"],denied_cidrs:$denied}' > "$state/external-network.json"
  [[ -f $state/public-egress.json ]] || jq -n --argjson denied "$special" \
    --arg address "${LOCAL_DNS_ADDRESS:-1.1.1.1:853}" --arg name "${LOCAL_DNS_NAME:-cloudflare-dns.com}" \
    '{dns_address:$address,dns_server_name:$name,denied_ipv4:($denied+["172.16.0.0/12"])}' > "$state/public-egress.json"
  FENDERS_DATABASE_URL=postgresql://postgres:local@127.0.0.1:$pg_port/fenders \
    setsid nohup "$bin/fenders-control-plane" --state "$state/control" --host 127.0.0.1 \
    --port $manage_port --internal-port $internal_port --gateway-port $gateway_port \
    --run-channel-port $channel_port --run-channel-endpoint "https://127.0.0.1:$channel_port" \
    --ca "$state/pki/ca.pem" --cert "$state/pki/control.pem" --key "$state/pki/control.key" \
    --external-network "$state/external-network.json" --public-egress "$state/public-egress.json" \
    ${LOCAL_CONTROL_ARGS:-} >> "$state/control.log" 2>&1 < /dev/null &
  echo $! > "$state/control.pid"
  until [[ -s $state/control/operator.token ]] && curl -s --cacert "$state/pki/ca.pem" -o /dev/null "$manage/"; do
    running "$state/control.pid" || { tail -5 "$state/control.log" >&2; exit 1; }
    sleep 1
  done
  # Public HTTPS is used only under the resolver configuration the operator
  # activated: here, whichever this control plane was started with.
  local policy
  policy=$(api GET /public-egress-policy)
  if [[ $(jq -r '.enabled and .digest == .configured_digest' <<<"$policy") != true ]]; then
    api PUT /public-egress-policy "$(jq '{expected_revision:.revision,enabled:true,digest:.configured_digest}' <<<"$policy")" >/dev/null
  fi
}

down() {
  if running "$state/node.pid"; then sudo kill "$(cat "$state/node.pid")" || true; fi
  if running "$state/control.pid"; then kill "$(cat "$state/control.pid")" || true; fi
  sleep 1
  if [[ -d $cgroup ]]; then
    echo 1 | sudo tee "$cgroup/cgroup.kill" >/dev/null 2>&1 || true
    sleep 1
    sudo find "$cgroup" -depth -type d -exec rmdir {} + 2>/dev/null || true
  fi
  docker stop "$pg" >/dev/null 2>&1 || true
  rm -f "$state/node.pid" "$state/control.pid"
}

up() {
  for file in "$build/fenders-node" "$build/fenders-shim" "$build/launch" "$build/runtime.elf" \
    "$build/compile" "$bin/fenders-control-plane" "$bin/fenders-pki"; do
    [[ -f $file ]] || { echo "missing $file: run make build-node" >&2; exit 2; }
  done
  [[ -c /dev/kvm ]] && sudo -n true
  down
  mkdir -p "$state"
  if ! docker start "$pg" >/dev/null 2>&1; then
    docker run -d --name "$pg" -p 127.0.0.1:$pg_port:5432 -e POSTGRES_PASSWORD=local \
      -e POSTGRES_DB=fenders -v "$pg":/var/lib/postgresql/data postgres:17-alpine >/dev/null
  fi
  # Asked over TCP: on a new data directory the image first runs a server
  # that listens on its socket alone, says it is ready there, and restarts.
  until docker exec "$pg" pg_isready -q -h 127.0.0.1 -U postgres; do sleep 1; done
  sleep 1
  [[ -f $state/pins.json ]] || "$bin/fenders-pki" --output "$state/pki" \
    --identity control=127.0.0.1,localhost --identity node=127.0.0.1 > "$state/pins.json"

  start_control

  # One workspace, project and node, made once.
  if [[ ! -f $state/scope.json ]]; then
    tenant=$(api POST /workspaces '{"name":"local","allowance":{"cpu_percent":800,"memory_mib":4096,"storage_bytes":4294967296,"instances":8,"transfer_bytes":4294967296}}' | jq -er .id)
    project=$(api POST "/workspaces/$tenant/projects" '{"name":"main"}' | jq -er .id)
    node=$(api POST /nodes "$(jq -n --arg pin "$(jq -er .node "$state/pins.json")" \
      --arg endpoint "https://127.0.0.1:$node_port" \
      '{name:"this-machine",cert_sha256:$pin,endpoint:$endpoint,backend:"wasm",architecture:"x86_64",
        runtime:"wasmtime-50.0.0-fenders-v1",cpu_percent:400,memory_mib:4096,instances:8}')" | jq -er .id)
    jq -n --arg tenant "$tenant" --arg project "$project" --arg node "$node" \
      '{tenant:$tenant,project:$project,node:$node}' > "$state/scope.json"
  fi

  sudo install -d -m 0755 "$stage" "$stage/build"
  sudo cp "$build"/{fenders-node,fenders-shim,launch,runtime.elf,compile} "$stage/build/"
  sudo chmod -R a+rX "$stage/build"
  local budget=()
  if [[ ${LOCAL_EGRESS_BUDGET:-1} == 1 ]]; then
    budget=(--egress-budget)
    api PATCH "/nodes/$(jq -er .node "$state/scope.json")" "$(jq -n \
      --arg launcher "$(sha256sum "$stage/build/launch" | cut -d' ' -f1)" \
      '{egress_budget_launcher:$launcher,egress_budget_required:true}')" >/dev/null
  else
    api PATCH "/nodes/$(jq -er .node "$state/scope.json")" '{"egress_budget_required":false}' >/dev/null
  fi
  sudo setsid nohup "$stage/build/fenders-node" --state "$stage/state" --build "$stage/build" \
    --cgroup-root "$cgroup" --control "https://127.0.0.1:$internal_port" \
    --control-pin "$(jq -er .control "$state/pins.json")" \
    --ca "$state/pki/ca.pem" --cert "$state/pki/node.pem" --key "$state/pki/node.key" \
    --cpu-percent 400 --memory-mib 4096 --max-instances 8 --port $node_port \
    --local-destinations --nested-virtualization \
    --metrics-listen 127.0.0.1:19464 ${WARM_RUNS:+--warm-runs "$WARM_RUNS"} "${budget[@]}" > /dev/null 2>> "$state/node.log" < /dev/null &
  sleep 1
  pgrep -f "$stage/build/fenders-node --state" | head -1 > "$state/node.pid"
  for _ in $(seq 30); do
    [[ $(api GET /nodes | jq -r '.items[0].observed_confinement // empty') == landlock6-seccomp-v2 ]] && break
    sleep 1
  done
  status
}

status() {
  running "$state/control.pid" && echo "control plane  running  $manage  (log: $state/control.log)" \
    || echo "control plane  stopped"
  running "$state/node.pid" && echo "node           running  https://127.0.0.1:$node_port  (log: $state/node.log)" \
    || echo "node           stopped"
  docker ps --format '{{.Names}}' | grep -qx "$pg" && echo "postgresql     running  127.0.0.1:$pg_port (container $pg)" \
    || echo "postgresql     stopped"
  if running "$state/control.pid"; then
    echo "management api $manage/v1   token: $state/control/operator.token   CA: $state/pki/ca.pem"
    echo "api contract   $manage/api/openapi.json"
    api GET /nodes | jq -r '.items[] | "node \(.name): confinement=\(.observed_confinement) last_seen=\(.last_seen)"'
    jq -r '"workspace \(.tenant)  project \(.project)"' "$state/scope.json"
  fi
}

run() {
  scope=/workspaces/$(jq -er .tenant "$state/scope.json")/projects/$(jq -er .project "$state/scope.json")
  artifact=$(curl -sS --fail-with-body --cacert "$state/pki/ca.pem" -X POST \
    -H "Authorization: Bearer $(cat "$state/control/operator.token")" \
    -H "Idempotency-Key: local-artifact-$RANDOM-$RANDOM" -H 'Content-Type: application/wasm' \
    --data-binary @"$build/example-command.wasm" "$manage/v1$scope/artifacts" | jq -er .id)
  for _ in $(seq 60); do
    [[ $(api GET "$scope/artifacts/$artifact/inspection" | jq -r .state) == valid ]] && break
    sleep 1
  done
  app=$(api POST "$scope/apps/deploy" "$(jq -n --arg a "$artifact" --arg n "example-$RANDOM" \
    '{name:$n,artifact_id:$a,triggers:{http:false,manual:true}}')" | jq -er '.app.id // .app_id // .resource_id // .id')
  for _ in $(seq 60); do
    [[ $(api GET "$scope/apps/$app" | jq -r .state) == ready ]] && break
    sleep 1
  done
  run=$(api POST "$scope/apps/$app/runs" '{}' | jq -er '.run.id // .run_id // .resource_id // .id')
  for _ in $(seq 60); do
    result=$(api GET "$scope/apps/$app/runs/$run")
    case $(jq -r .state <<<"$result") in succeeded|failed|cancelled) break ;; esac
    sleep 1
  done
  jq --arg app "$app" '{app: $app, run: .id, state, exit_code}' <<<"$result"
}

case ${1:-} in
  up) up ;;
  down) down; echo stopped ;;
  status) status ;;
  run) run ;;
  destroy)
    down
    docker rm -f "$pg" >/dev/null 2>&1 || true
    docker volume rm "$pg" >/dev/null 2>&1 || true
    sudo rm -rf "$stage"
    rm -rf "$state"
    echo destroyed
    ;;
  *) sed -n 2,18p "$0" >&2; exit 2 ;;
esac
