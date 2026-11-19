#!/usr/bin/env bash
# The outbound byte limit end to end, against the local environment
# (scripts/local_env.sh up, which runs its node under the limit): runs that
# send to a connection are granted bytes from the workspace's transfer
# allowance, and one that would send more than is left is cut off.
#
#   bash scripts/verify_egress_limit_live.sh [OUTPUT_DIR]
#
# The endpoint is a container started here on Docker's bridge that reads and
# discards what it is sent (removed at the end). The workspace's allowance is
# lowered for the check and put back at the end. Passes when
#  - a run that sends 4 MiB within the allowance succeeds, and exactly those
#    bytes are counted against the allowance, none left held;
#  - with 3 MiB of allowance left, a run that would send 8 MiB sends 3 MiB
#    and is ended there, reading as failed because the transfer allowance was
#    exceeded, and the allowance then stands exactly used up, not exceeded;
#  - the next run of that app, with nothing left, is ended before it sends;
#  - a run with no connection still succeeds with the allowance used up.
# Leaves the apps, the registered connection and the runs in the project.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
state=${LOCAL_STATE:-$repo/run/local}
out=${1:-$repo/run/egress-limit-live-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$out"
manage=https://127.0.0.1:19090
target=fenders-live-sink
mib=1048576
api() { # METHOD PATH [JSON]
  curl -sS --fail-with-body --cacert "$state/pki/ca.pem" -X "$1" \
    -H "Authorization: Bearer $(cat "$state/control/operator.token")" \
    -H "Idempotency-Key: egress-$(date +%s%N)" -H 'Content-Type: application/json' \
    ${3:+-d "$3"} "$manage/v1$2"
}
upload() { # FILE
  local id
  id=$(curl -sS --fail-with-body --cacert "$state/pki/ca.pem" -X POST \
    -H "Authorization: Bearer $(cat "$state/control/operator.token")" \
    -H "Idempotency-Key: egress-artifact-$(date +%s%N)" -H 'Content-Type: application/wasm' \
    --data-binary @"$1" "$manage/v1$scope/artifacts" | jq -er .id)
  for _ in $(seq 90); do
    [[ $(api GET "$scope/artifacts/$id/inspection" | jq -r '.state // empty') == valid ]] && break
    sleep 1
  done
  echo "$id"
}
deploy() { # NAME ARTIFACT ENV_JSON CONNECTIONS_JSON
  local app
  app=$(api POST "$scope/apps/deploy" "$(jq -n --arg n "$1" --arg a "$2" --argjson env "$3" --argjson c "$4" \
    '{name:$n,artifact_id:$a,triggers:{http:false,manual:true},configuration:{env:$env},connections:$c}')" |
    jq -er '.app.id // .app_id // .resource_id // .id')
  for _ in $(seq 60); do
    [[ $(api GET "$scope/apps/$app" | jq -r .state) == ready ]] && break
    sleep 1
  done
  echo "$app"
}
run() { # APP NAME: starts a run, waits for its end, keeps the run and its output
  local id
  id=$(api POST "$scope/apps/$1/runs" '{}' | jq -er '.run.id // .run_id // .resource_id // .id')
  for _ in $(seq 120); do
    api GET "$scope/apps/$1/runs/$id" > "$out/$2.run.json"
    case $(jq -r .state "$out/$2.run.json") in succeeded|failed|cancelled) break ;; esac
    sleep 1
  done
  for _ in $(seq 10); do
    api GET "$scope/apps/$1/logs?run_id=$id" > "$out/$2.logs.json"
    [[ $(jq -r '.collection.complete // 0' "$out/$2.logs.json") == 1 ]] && break
    sleep 1
  done
  jq -r '[.items[] | .bytes | @base64d] | join("")' "$out/$2.logs.json" > "$out/$2.txt"
}
transfer() { # NAME: the workspace's transfer allowance, what is counted against it and what is held,
  # leaving out what gateways hold as leases of it: passed to no one, and
  # given back when the workspace has had no traffic for 30 seconds
  api GET "/workspaces/$tenant/usage" |
    jq '{allowance: .allowance.transfer_bytes, counted: .transfer_allowance.bytes, held: (.transfer_allowance.reserved_bytes - .transfer_allowance.gateway_leased_bytes)}' > "$out/$1.transfer.json"
}
allow() { # BYTES: sets the workspace's transfer allowance, keeping the rest
  api PATCH "/workspaces/$tenant" "$(jq --argjson bytes "$1" \
    '{allowance: (.allowance | {cpu_percent,memory_mib,storage_bytes,instances} + {transfer_bytes:$bytes})}' "$out/usage-before.json")" >/dev/null
}

tenant=$(jq -er .tenant "$state/scope.json")
scope=/workspaces/$tenant/projects/$(jq -er .project "$state/scope.json")
tag=$(date +%H%M%S)
api GET /nodes | jq -e '.items[0] | .egress_budget_required and .observed_egress_budget != null' >/dev/null ||
  { echo 'the local node does not run under the outbound byte limit' >&2; exit 2; }
api GET "/workspaces/$tenant/usage" > "$out/usage-before.json"
original=$(jq -er .allowance.transfer_bytes "$out/usage-before.json")
docker rm -f "$target" >/dev/null 2>&1 || true
docker run -d --name "$target" postgres:17-alpine sh -c 'nc -lk -p 9000 -e sh -c "cat >/dev/null"' >/dev/null
trap 'docker rm -f "$target" >/dev/null 2>&1 || true; allow "$original" || true' EXIT
address=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$target")
sleep 1

command=$(upload "$repo/build/node/example-command.wasm")
endpoint=$(api POST "$scope/connections" \
  "$(jq -n --arg n "live-sink-$tag" --arg h "$address" '{name:$n,host:$h,port:9000}')" | jq -er .resource_id)
connection=$(jq -n --arg c "$endpoint" '[{connection_id:$c}]')
sending() { jq -n --arg bytes "$1" '{TEST_MODE:"connect",TEST_CONNECT_BULK:$bytes}'; }

# Within the allowance.
transfer start
within=$(deploy "send-$tag" "$command" "$(sending $((4 * mib)))" "$connection")
run "$within" within
transfer after-within

# Three mebibytes left, eight to send.
allow $(($(jq -er .counted "$out/after-within.transfer.json") + 3 * mib))
limited=$(deploy "limited-$tag" "$command" "$(sending $((8 * mib)))" "$connection")
run "$limited" cut-off
transfer after-cut-off

# Nothing left.
run "$limited" nothing-left
transfer after-nothing-left

# A run that asks for no connection is not under the limit.
plain=$(deploy "plain-$tag" "$command" '{}' '[]')
run "$plain" no-connection

jq -n --argjson mib "$mib" \
  --slurpfile start "$out/start.transfer.json" --slurpfile after_within "$out/after-within.transfer.json" \
  --slurpfile after_cut "$out/after-cut-off.transfer.json" --slurpfile after_nothing "$out/after-nothing-left.transfer.json" \
  --slurpfile within "$out/within.run.json" --rawfile within_out "$out/within.txt" \
  --slurpfile cut "$out/cut-off.run.json" --rawfile cut_out "$out/cut-off.txt" \
  --slurpfile nothing "$out/nothing-left.run.json" --rawfile nothing_out "$out/nothing-left.txt" \
  --slurpfile plain "$out/no-connection.run.json" '
  def sent($text): [$text | split("\n")[] | select(test("^sent [0-9]+ bytes$")) | split(" ")[1] | tonumber] | max // 0;
  def run($r): {state: $r[0].state, exit_code: $r[0].exit_code, reason: $r[0].reason, diagnostic: $r[0].diagnostic.summary};
  {within_the_allowance: (run($within) + {sent_bytes: sent($within_out),
      counted_bytes: ($after_within[0].counted - $start[0].counted), held_after: $after_within[0].held}),
   three_mebibytes_left_eight_to_send: (run($cut) + {sent_bytes: sent($cut_out),
      allowance: $after_cut[0].allowance, counted_after: $after_cut[0].counted, held_after: $after_cut[0].held}),
   nothing_left: (run($nothing) + {sent_bytes: sent($nothing_out),
      counted_after: $after_nothing[0].counted, held_after: $after_nothing[0].held}),
   no_connection: run($plain)}
  | .passed = (
      .within_the_allowance.state == "succeeded" and .within_the_allowance.sent_bytes == 4 * $mib
      and .within_the_allowance.counted_bytes == 4 * $mib and .within_the_allowance.held_after == 0
      and .three_mebibytes_left_eight_to_send.state == "failed"
      and .three_mebibytes_left_eight_to_send.reason == "outbound-allowance-denied"
      and .three_mebibytes_left_eight_to_send.sent_bytes == 3 * $mib
      and .three_mebibytes_left_eight_to_send.counted_after == .three_mebibytes_left_eight_to_send.allowance
      and .three_mebibytes_left_eight_to_send.held_after == 0
      and .nothing_left.state == "failed" and .nothing_left.reason == "outbound-allowance-denied"
      and .nothing_left.sent_bytes == 0
      and .nothing_left.counted_after == .three_mebibytes_left_eight_to_send.allowance
      and .nothing_left.held_after == 0
      and .no_connection.state == "succeeded")' | tee "$out/result.json"
jq -e .passed "$out/result.json" >/dev/null
