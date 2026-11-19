#!/usr/bin/env bash
# HTTP apps end to end, against the local environment (scripts/local_env.sh up):
# apps with the HTTP trigger, served by guests on a real node whose shims pull
# their requests over the run channel.
#
#   bash scripts/verify_http_live.sh [OUTPUT_DIR]
#
# Requests go to the gateway listener (port 19092) with the app's host name
# resolved to this machine; its certificate is the control plane's, not one
# for the application domain, so it is not verified here. Passes when
#  - an app with the HTTP trigger reads as serving, and requests through the
#    gateway return what its component answers, a posted body included;
#  - a request the component never answers (it spins) gets 502, and the next
#    request is answered;
#  - the API's sample request returns the component's answer;
#  - each request is listed in the app's events with its status;
#  - a 16 MiB upload and a 16 MiB download pass whole, a response of
#    server-sent events arrives event by event, and exactly the bytes of
#    those bodies are counted against the workspace's transfer allowance,
#    with no more held than the gateway's lease of it (64 MiB at most);
#  - with 2 MiB of allowance left, an 8 MiB download is cut at 2 MiB, what
#    is counted and held is not more than the allowance, and the next
#    request is refused;
#  - an app allowed three executions grows to three under six clients with
#    no request failing, and shrinks back to one when the load ends;
#  - a new release of an app under steady load takes over on another
#    execution with no request failing;
#  - an app that is not kept warm goes idle with no execution, and its next
#    request starts one and is answered;
#  - a request to a stopped app is refused, not held.
# The workspace's transfer allowance is lowered for the cut and put back.
# Leaves the apps and their records in the project; stops their executions.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
state=${LOCAL_STATE:-$repo/run/local}
out=${1:-$repo/run/http-live-$(date +%Y%m%d-%H%M%S)}
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
api GET "/workspaces/$tenant/usage" > "$out/usage-before.json"
original=$(jq -er .allowance.transfer_bytes "$out/usage-before.json")
trap 'allow "$original" || true' EXIT
mib=1048576
tag=$(date +%H%M%S)
artifact=$(upload "$repo/build/node/example-http.wasm")

warm=$(deploy "web-$tag" "$artifact" '{}')
await "$warm" serving 60
domain=$(api GET "$scope/apps/$warm/http" | jq -er .url | sed -E 's|^https://app-[0-9a-f]+\.||')
request "$warm" hello /hello
request "$warm" posted -X POST -H 'Content-Type: text/plain' --data-binary 'a posted body' /orders
request "$warm" spin /spin
request "$warm" after /after
api POST "$scope/apps/$warm/http-sample" '{"path":"/sample"}' > "$out/sample.json"
sleep 1
api GET "$scope/apps/$warm/events?limit=20" > "$out/events.json"

# Bodies passed on as they come, and counted.
sleep 1
transfer before-streams
head -c $((16 * mib)) /dev/zero > "$out/upload.bin"
request "$warm" upload -X POST -H 'Content-Type: application/octet-stream' --data-binary "@$out/upload.bin" /count
request "$warm" download "/bytes/$((16 * mib))"
request "$warm" sse -N /events/8
sleep 2
transfer after-streams
# Two blocks of allowance left, and a download of eight.
allow $(($(jq -er .counted "$out/after-streams.transfer.json") + 2 * mib))
request "$warm" cut "/bytes/$((8 * mib))"
sleep 2
transfer after-cut
request "$warm" refused /refused
allow "$original"
rm -f "$out/upload.bin"

# Scale: six clients on an app that serves one request at a time and may
# have three executions.
scaled=$(deploy "scaled-$tag" "$artifact" '{"scale":{"min":1,"max":3}}')
await "$scaled" serving 60
host=app-$scaled.$domain
: > "$out/load.codes"
for client in $(seq 6); do
  ( for _ in $(seq 30); do
      curl -sk --max-time 30 --resolve "$host:$gateway_port:127.0.0.1" -o /dev/null \
        -w '%{http_code}\n' "https://$host:$gateway_port/events/3" >> "$out/load.codes" || true
    done ) &
done
peak=1
while [[ -n $(jobs -r) ]]; do
  now=$(api GET "$scope/apps/$scaled/http" | jq -r .executions)
  (( now > peak )) && peak=$now
  sleep 1
done
wait
settled=
for _ in $(seq 150); do
  settled=$(api GET "$scope/apps/$scaled/http" | jq -r .executions)
  [[ $settled == 1 ]] && break
  sleep 1
done
jq -n --argjson peak "$peak" --argjson settled "$settled" --rawfile codes "$out/load.codes" \
  '{requests: ($codes | split("\n") | map(select(. != "")) | length),
    not_200: ($codes | split("\n") | map(select(. != "" and . != "200")) | length),
    most_executions: $peak, executions_after_the_load: $settled}' > "$out/scale.json"

# A new release under steady load: three clients, half a second a request.
host=app-$warm.$domain
before=$(api GET "$scope/apps/$warm/http" | jq -r .execution_id)
: > "$out/roll.codes"
for client in $(seq 3); do
  ( for _ in $(seq 40); do
      curl -sk --max-time 30 --resolve "$host:$gateway_port:127.0.0.1" -o /dev/null \
        -w '%{http_code}\n' "https://$host:$gateway_port/wait" >> "$out/roll.codes" || true
    done ) &
done
sleep 3
api GET "$scope/apps/$warm" > "$out/roll.app.json"
rollout=$(api POST "$scope/apps/$warm/releases" "$(jq '{version_id: .latest_code.id, expected_revision: .revision}' "$out/roll.app.json")" | jq -er .id)
wait
for _ in $(seq 60); do
  api GET "$scope/operations/$rollout" > "$out/roll.operation.json"
  [[ $(jq -r .state "$out/roll.operation.json") != pending ]] && break
  sleep 1
done
jq -n --arg before "$before" --arg after "$(api GET "$scope/apps/$warm/http" | jq -r .execution_id)" \
  --rawfile codes "$out/roll.codes" --slurpfile operation "$out/roll.operation.json" \
  '{requests: ($codes | split("\n") | map(select(. != "")) | length),
    not_200: ($codes | split("\n") | map(select(. != "" and . != "200")) | length),
    operation: $operation[0].state, another_execution_serves: ($before != $after)}' > "$out/roll.json"

# Not kept warm: idle after a minute without a request, then woken by one.
cold=$(deploy "demand-$tag" "$artifact" '{"keep_warm":false}')
await "$cold" serving 60
request "$cold" first /first
await "$cold" idle 120
api GET "$scope/apps/$cold/http" > "$out/idle.json"
request "$cold" woken /woken
api GET "$scope/apps/$cold/http" > "$out/woken-state.json"

# Stopped: a request is refused at once.
for app in "$warm" "$cold" "$scaled"; do
  revision=$(api GET "$scope/apps/$app" | jq -er .revision)
  api PATCH "$scope/apps/$app" \
    "$(jq -n --argjson r "$revision" '{desired:"stopped",expected_revision:$r}')" > /dev/null
done
await "$warm" disabled 60
request "$warm" stopped /stopped

jq -n --arg tag "$tag" --arg domain "$domain" \
  --slurpfile hello "$out/hello.json" --rawfile hello_body "$out/hello.body" \
  --slurpfile posted "$out/posted.json" --rawfile posted_body "$out/posted.body" \
  --slurpfile spin "$out/spin.json" --slurpfile after "$out/after.json" --rawfile after_body "$out/after.body" \
  --slurpfile sample "$out/sample.json" --slurpfile events "$out/events.json" \
  --slurpfile upload "$out/upload.json" --rawfile upload_body "$out/upload.body" \
  --slurpfile download "$out/download.json" --slurpfile sse "$out/sse.json" --rawfile sse_body "$out/sse.body" \
  --slurpfile before_streams "$out/before-streams.transfer.json" --slurpfile after_streams "$out/after-streams.transfer.json" \
  --slurpfile cut "$out/cut.json" --slurpfile after_cut "$out/after-cut.transfer.json" --slurpfile refused "$out/refused.json" \
  --argjson mib "$mib" --slurpfile scale "$out/scale.json" --slurpfile roll "$out/roll.json" \
  --slurpfile first "$out/first.json" --slurpfile idle "$out/idle.json" \
  --slurpfile woken "$out/woken.json" --rawfile woken_body "$out/woken.body" \
  --slurpfile woken_state "$out/woken-state.json" --slurpfile stopped "$out/stopped.json" '
  def got($r; $body): $r[0] + {body: $body};
  {tag: $tag, application_domain: $domain,
   kept_warm: {
     get: got($hello; $hello_body), post: got($posted; $posted_body),
     never_answered: $spin[0], next_after_it: got($after; $after_body),
     sample: ($sample[0] | {outcome, status, body: (.body | @base64d), duration_ms}),
     events: [$events[0].items[] | select(.path != null) | {method, path, state, http_status}]},
   streamed: {
     upload_16_mib: got($upload; $upload_body),
     download_16_mib: $download[0],
     server_sent_events: ($sse[0] + {events: ($sse_body | [scan("data: event")] | length)}),
     counted_bytes: ($after_streams[0].counted - $before_streams[0].counted),
     held_after: $after_streams[0].held},
   two_mebibytes_left_eight_to_download: {
     download: $cut[0], allowance: $after_cut[0].allowance,
     counted_after: $after_cut[0].counted, held_after: $after_cut[0].held,
     next_request: $refused[0]},
   six_clients_up_to_three_executions: $scale[0],
   new_release_under_load: $roll[0],
   not_kept_warm: {
     first: $first[0], idle: ($idle[0] | {state, execution_id}),
     woken: got($woken; $woken_body), then: ($woken_state[0] | {state})},
   stopped: $stopped[0]}
  | .passed = (
      .kept_warm.get.status == 200 and .kept_warm.get.body == "fenders:/hello"
      and .kept_warm.post.status == 200 and .kept_warm.post.body == "a posted body"
      and .kept_warm.never_answered.status == 502
      and .kept_warm.next_after_it.status == 200 and .kept_warm.next_after_it.body == "fenders:/after"
      and .kept_warm.sample.outcome == "response" and .kept_warm.sample.status == 200
      and .kept_warm.sample.body == "fenders:/sample"
      and (.kept_warm.events | any(.path == "/hello" and .state == "succeeded" and .http_status == 200))
      and (.kept_warm.events | any(.path == "/orders" and .method == "POST" and .http_status == 200))
      and (.kept_warm.events | any(.path == "/spin" and .state == "failed" and .http_status == 502))
      and .streamed.upload_16_mib.status == 200 and .streamed.upload_16_mib.body == "count:\(16 * $mib)"
      and .streamed.download_16_mib.status == 200 and .streamed.download_16_mib.received_bytes == 16 * $mib
      and .streamed.server_sent_events.events == 8
      and .streamed.server_sent_events.first_byte_seconds < 1 and .streamed.server_sent_events.seconds > 2
      and .streamed.counted_bytes == 32 * $mib + ("count:\(16 * $mib)" | length) + .streamed.server_sent_events.received_bytes
      and .streamed.held_after <= 64 * $mib
      and .two_mebibytes_left_eight_to_download.download.received_bytes <= 2 * $mib
      and .two_mebibytes_left_eight_to_download.download.received_bytes > 2 * $mib - 65536
      and .two_mebibytes_left_eight_to_download.counted_after <= .two_mebibytes_left_eight_to_download.allowance
      and .two_mebibytes_left_eight_to_download.counted_after + .two_mebibytes_left_eight_to_download.held_after
          <= .two_mebibytes_left_eight_to_download.allowance
      and .two_mebibytes_left_eight_to_download.next_request.status == 429
      and .six_clients_up_to_three_executions.requests == 180
      and .six_clients_up_to_three_executions.not_200 == 0
      and .six_clients_up_to_three_executions.most_executions == 3
      and .six_clients_up_to_three_executions.executions_after_the_load == 1
      and .new_release_under_load.requests == 120 and .new_release_under_load.not_200 == 0
      and .new_release_under_load.operation == "succeeded"
      and .new_release_under_load.another_execution_serves
      and .not_kept_warm.first.status == 200
      and .not_kept_warm.idle.state == "idle" and .not_kept_warm.idle.execution_id == null
      and .not_kept_warm.woken.status == 200 and .not_kept_warm.woken.body == "fenders:/woken"
      and .not_kept_warm.then.state == "serving"
      and .stopped.status == 503 and .stopped.seconds < 2)' | tee "$out/result.json"
jq -e .passed "$out/result.json" >/dev/null
