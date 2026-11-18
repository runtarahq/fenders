#!/usr/bin/env bash
# What an anonymous client of the gateway cannot do to an app, against the
# local environment (scripts/local_env.sh up), on a real node.
#
#   bash scripts/verify_gateway_limits_live.sh [OUTPUT_DIR]
#
# Passes when
#  - a request whose target is too long for a head the shim reads is refused
#    (414 from the gateway over HTTP/1.1, 431 from its HTTP/2 framing) and
#    wakes nothing: an idle app stays idle;
#  - such requests sent while an app is starting do not end its execution:
#    the app serves, with no restart counted, and is never blocked;
#  - requests whose clients go away before they are answered hold none of
#    the workspace's transfer allowance a few seconds later, and the next
#    request is answered rather than refused for too many in flight.
# Leaves the app and its records in the project; stops its execution.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
state=$repo/run/local
out=${1:-$repo/run/gateway-limits-live-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$out"
manage=https://127.0.0.1:19090
gateway_port=19092
api() { # METHOD PATH [JSON]
  curl -sS --fail-with-body --cacert "$state/pki/ca.pem" -X "$1" \
    -H "Authorization: Bearer $(cat "$state/control/operator.token")" \
    -H "Idempotency-Key: http-$(date +%s%N)" -H 'Content-Type: application/json' \
    ${3:+-d "$3"} "$manage/v1$2"
}
upload() { # FILE
  local id
  id=$(curl -sS --fail-with-body --cacert "$state/pki/ca.pem" -X POST \
    -H "Authorization: Bearer $(cat "$state/control/operator.token")" \
    -H "Idempotency-Key: http-artifact-$(date +%s%N)" -H 'Content-Type: application/wasm' \
    --data-binary @"$1" "$manage/v1$scope/artifacts" | jq -er .id)
  for _ in $(seq 90); do
    [[ $(api GET "$scope/artifacts/$id/inspection" | jq -r '.state // empty') == valid ]] && break
    sleep 1
  done
  echo "$id"
}
deploy() { # NAME ARTIFACT CONFIGURATION_JSON
  api POST "$scope/apps/deploy" "$(jq -n --arg n "$1" --arg a "$2" --argjson c "$3" \
    '{name:$n,artifact_id:$a,triggers:{http:true,manual:false},configuration:$c}')" |
    jq -er '.app.id // .app_id // .resource_id // .id'
}
http_state() { api GET "$scope/apps/$1/http" | jq -r .state; }
await() { # APP STATE SECONDS
  for _ in $(seq "$3"); do
    [[ $(http_state "$1") == "$2" ]] && return 0
    sleep 1
  done
  echo "app $1 did not become $2: $(api GET "$scope/apps/$1/http")" >&2
  return 1
}
request() { # APP NAME [CURL ARGS…] PATH: writes NAME.body and NAME.json
  local app=$1 name=$2 host
  shift 2
  host=app-$app.$domain
  curl -sk --max-time 30 --resolve "$host:$gateway_port:127.0.0.1" -o "$out/$name.body" \
    -w '{"status":%{http_code},"seconds":%{time_total},"first_byte_seconds":%{time_starttransfer},"received_bytes":%{size_download},"content_type":"%{content_type}"}' \
    "${@:1:$#-1}" "https://$host:$gateway_port${*: -1}" > "$out/$name.json" || true
}

transfer() { # NAME: the workspace's transfer allowance, what is counted against it and what is held
  api GET "/workspaces/$tenant/usage" |
    jq '{allowance: .allowance.transfer_bytes, counted: .transfer_allowance.bytes, held: .transfer_allowance.reserved_bytes}' > "$out/$1.transfer.json"
}
allow() { # BYTES: sets the workspace's transfer allowance, keeping the rest
  api PATCH "/workspaces/$tenant" "$(jq --argjson bytes "$1" \
    '{allowance: (.allowance | {cpu_percent,memory_mib,storage_bytes,instances} + {transfer_bytes:$bytes})}' "$out/usage-before.json")" >/dev/null
}

tenant=$(jq -er .tenant "$state/scope.json")
scope=/workspaces/$tenant/projects/$(jq -er .project "$state/scope.json")
tag=$(date +%H%M%S)
artifact=$(upload "$repo/build/node/example-http.wasm")
long=$(head -c 65000 /dev/zero | tr '\0' a)

app=$(deploy "limits-$tag" "$artifact" '{"keep_warm":false}')
await "$app" serving 60
domain=$(api GET "$scope/apps/$app/http" | jq -er .url | sed -E 's|^https://app-[0-9a-f]+\.||')
request "$app" first /first

# Idle, then a target no shim could read: refused, and nothing is woken.
await "$app" idle 120
request "$app" long-idle --http1.1 "/$long"
request "$app" long-idle-h2 --http2 "/$long"
sleep 3
api GET "$scope/apps/$app/http" > "$out/after-long-idle.json"

# The same while it starts: a request that fits wakes it, and long ones
# arrive beside it and after it.
request "$app" wake /wake &
for n in 1 2 3 4 5 6; do
  request "$app" "long-$n" --http1.1 "/$long"
  sleep 0.3
done
wait
await "$app" serving 60
request "$app" served /served
api GET "$scope/apps/$app/http" > "$out/after-long-starting.json"

# Clients that go away: each sends the start of a body and stops.
head -c 4194304 /dev/zero > "$out/slow.bin"
for n in $(seq 32); do
  curl -sk --max-time 0.4 --limit-rate 4k --resolve "app-$app.$domain:$gateway_port:127.0.0.1" \
    -o /dev/null -X POST --data-binary @"$out/slow.bin" \
    "https://app-$app.$domain:$gateway_port/abandoned" &
done
wait || true
rm -f "$out/slow.bin"
sleep 5
transfer after-abandoned
request "$app" after-abandoned /after-abandoned

revision=$(api GET "$scope/apps/$app" | jq -er .revision)
api PATCH "$scope/apps/$app" \
  "$(jq -n --argjson r "$revision" '{desired:"stopped",expected_revision:$r}')" > /dev/null

jq -n --slurpfile long_idle "$out/long-idle.json" --slurpfile long_h2 "$out/long-idle-h2.json" --slurpfile after_idle "$out/after-long-idle.json" \
  --slurpfile l1 "$out/long-1.json" --slurpfile l6 "$out/long-6.json" \
  --slurpfile wake "$out/wake.json" --slurpfile served "$out/served.json" \
  --rawfile served_body "$out/served.body" --slurpfile starting "$out/after-long-starting.json" \
  --slurpfile held "$out/after-abandoned.transfer.json" --slurpfile next "$out/after-abandoned.json" '
  {long_target_at_an_idle_app: {status: $long_idle[0].status, over_http2: $long_h2[0].status,
     state_after: $after_idle[0].state},
   long_targets_while_starting: {first: $l1[0].status, last: $l6[0].status, wake: $wake[0].status,
     served: $served[0].status, body: $served_body, state: $starting[0].state,
     reason: $starting[0].reason},
   abandoned: {held_bytes_after: $held[0].held, next: $next[0].status}}
  | .passed = (.long_target_at_an_idle_app == {status: 414, over_http2: 431, state_after: "idle"}
      and .long_targets_while_starting.first == 414 and .long_targets_while_starting.last == 414
      and .long_targets_while_starting.wake == 200 and .long_targets_while_starting.served == 200
      and .long_targets_while_starting.body == "fenders:/served"
      and .long_targets_while_starting.state == "serving"
      and .abandoned == {held_bytes_after: 0, next: 200})' | tee "$out/result.json"
jq -e .passed "$out/result.json" > /dev/null
