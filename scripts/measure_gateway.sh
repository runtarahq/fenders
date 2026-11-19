#!/usr/bin/env bash
# What the gateway serves, measured against the local environment
# (scripts/local_env.sh up): requests a second, how long they take, and how
# many transactions under the mutation lock each one costs.
#
#   bash scripts/measure_gateway.sh [OUTPUT_DIR]
#
# Makes WORKSPACES workspaces (4 unless said), each with one HTTP app of the
# example component serving CONCURRENCY requests at once (16), with limits
# and an allowance no run here reaches. Then, for SECONDS seconds each (15),
# with CLIENTS clients (32):
#   one-app         GET /hello of one app
#   many-workspaces GET /hello of every app in turn
#   large-bodies    GET /bytes/16777216 of one app, with 4 clients
# and for each, from GET /v1/control-plane/status before and after: the
# locked transactions made and the time they waited for the lock.
#
# The locked transactions counted are the whole process's, the scheduler's
# and the node's heartbeats among them: `idle` is the same span with no
# client, to be taken off.
#
# Needs target/release/fenders-load (cargo build --release -p
# fenders-control-plane --bin fenders-load). Writes OUTPUT_DIR/summary.json
# and prints it. Suspends and deletes the workspaces it made.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
state=${LOCAL_STATE:-$repo/run/local}
out=${1:-$repo/run/measure-gateway-$(date +%Y%m%d-%H%M%S)}
load=${LOCAL_BIN:-$repo/target/release}/fenders-load
workspaces=${WORKSPACES:-4} concurrency=${CONCURRENCY:-16}
seconds=${SECONDS_EACH:-15} clients=${CLIENTS:-32}
manage=https://127.0.0.1:19090
gateway_port=19092
mkdir -p "$out"
[[ -x $load ]] || { echo "missing $load: cargo build --release -p fenders-control-plane --bin fenders-load" >&2; exit 2; }
api() { # METHOD PATH [JSON]
  curl -sS --fail-with-body --cacert "$state/pki/ca.pem" -X "$1" \
    -H "Authorization: Bearer $(cat "$state/control/operator.token")" \
    -H "Idempotency-Key: measure-$(date +%s%N)" -H 'Content-Type: application/json' \
    ${3:+-d "$3"} "$manage/v1$2"
}
tag=$(date +%H%M%S)
made=()
remove() {
  for tenant in "${made[@]}"; do
    revision=$(api GET "/workspaces/$tenant" | jq -r .lifecycle_revision) || continue
    api POST "/workspaces/$tenant/lifecycle" \
      "$(jq -n --argjson r "$revision" '{expected_revision:$r,action:"suspend",reason:"measured"}')" >/dev/null || continue
    for _ in $(seq 60); do
      [[ $(api GET "/workspaces/$tenant" | jq -r .lifecycle_state) == suspended ]] && break
      sleep 1
    done
    api DELETE "/workspaces/$tenant" >/dev/null || true
  done
}
trap remove EXIT

urls=() large=
for index in $(seq "$workspaces"); do
  tenant=$(api POST /workspaces "$(jq -n --arg n "measure-$tag-$index" \
    '{name:$n,allowance:{cpu_percent:100,memory_mib:1024,storage_bytes:1073741824,instances:1,transfer_bytes:1099511627776}}')" | jq -er .id)
  made+=("$tenant")
  api PATCH "/workspaces/$tenant/http-limits" '{"concurrent_requests":10000,"requests_per_minute":10000000}' >/dev/null
  scope=/workspaces/$tenant/projects/$(api GET "/workspaces/$tenant/projects" | jq -er '.items[0].id')
  artifact=$(curl -sS --fail-with-body --cacert "$state/pki/ca.pem" -X POST \
    -H "Authorization: Bearer $(cat "$state/control/operator.token")" \
    -H "Idempotency-Key: measure-artifact-$(date +%s%N)" -H 'Content-Type: application/wasm' \
    --data-binary @"$repo/build/node/example-http.wasm" "$manage/v1$scope/artifacts" | jq -er .id)
  for _ in $(seq 90); do
    [[ $(api GET "$scope/artifacts/$artifact/inspection" | jq -r '.state // empty') == valid ]] && break
    sleep 1
  done
  app=$(api POST "$scope/apps/deploy" "$(jq -n --arg a "$artifact" --argjson c "$concurrency" \
    '{name:"measured",artifact_id:$a,triggers:{http:true,manual:false},configuration:{concurrency:$c}}')" |
    jq -er '.app.id // .app_id // .resource_id // .id')
  for _ in $(seq 90); do
    [[ $(api GET "$scope/apps/$app/http" | jq -r .state) == serving ]] && break
    sleep 1
  done
  url=$(api GET "$scope/apps/$app/http" | jq -er .url)
  host=${url#https://}
  urls+=("https://$host:$gateway_port")
done

counted() { api GET /control-plane/status | jq -c '{locked: .database.locked_transactions, wait_ms: .database.lock_wait_ms, admitted: .gateway.admitted}'; }
measure() { # NAME CLIENTS URL…
  local name=$1 with=$2 before after
  shift 2
  before=$(counted)
  if (( with > 0 )); then
    "$load" --insecure --connect "127.0.0.1:$gateway_port" --clients "$with" --seconds "$seconds" "$@" > "$out/$name.load.json"
  else
    sleep "$seconds"
    echo '{"requests":0}' > "$out/$name.load.json"
  fi
  after=$(counted)
  jq -n --arg name "$name" --argjson before "$before" --argjson after "$after" --slurpfile load "$out/$name.load.json" \
    '{name: $name, load: $load[0],
      locked_transactions: ($after.locked - $before.locked),
      lock_wait_ms: ($after.wait_ms - $before.wait_ms),
      admitted: ($after.admitted - $before.admitted)}' > "$out/$name.json"
}
# Once through each, so that nothing measured is a first request.
for url in "${urls[@]}"; do
  curl -sk -o /dev/null --resolve "${url#https://}:127.0.0.1" "$url/hello" || true
done
measure idle 0
measure one-app "$clients" "${urls[0]}/hello"
measure many-workspaces "$clients" "${urls[@]/%//hello}"
measure large-bodies 4 "${urls[0]}/bytes/16777216"

jq -n --argjson seconds "$seconds" --argjson workspaces "$workspaces" --argjson concurrency "$concurrency" \
  --arg commit "$(git -C "$repo" rev-parse --short HEAD)" \
  --slurpfile idle "$out/idle.json" --slurpfile one "$out/one-app.json" \
  --slurpfile many "$out/many-workspaces.json" --slurpfile large "$out/large-bodies.json" '
  def row: . as $r | ($r.locked_transactions - $idle[0].locked_transactions) as $locked |
    {requests_a_second: $r.load.requests_a_second, latency_ms: $r.load.latency_ms, statuses: $r.load.statuses,
     locked_transactions_a_request: (if $r.load.requests > 0 then ($locked / $r.load.requests * 100 | round / 100) else null end),
     lock_wait_ms_a_request: (if $r.load.requests > 0 then ($r.lock_wait_ms / $r.load.requests * 100 | round / 100) else null end)};
  {commit: $commit, seconds_each: $seconds, workspaces: $workspaces, concurrency: $concurrency,
   idle_locked_transactions: $idle[0].locked_transactions,
   one_app: ($one[0] | row), many_workspaces: ($many[0] | row), large_bodies: ($large[0] | row)}' | tee "$out/summary.json"
