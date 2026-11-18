#!/usr/bin/env bash
# Connections end to end, against the local environment (scripts/local_env.sh up):
# a TCP endpoint and a public HTTPS origin given to apps as connections, used
# by their runs on a real node, and taken away from a run in flight.
#
#   bash scripts/verify_connections_live.sh [OUTPUT_DIR]
#
# The TCP endpoint is a PostgreSQL container started here on Docker's bridge
# (removed at the end); the HTTPS origin is https://example.com. Passes when
#  - a run with the endpoint as a connection reaches it, and is refused another
#    port of the same address;
#  - a run with the same program and the endpoint's address in its plain
#    configuration, but no connection, is refused;
#  - a run with the origin as a connection fetches it twice over verified TLS;
#  - removing the endpoint from an app whose run is connecting once a second
#    stops that run, which then reads as cancelled because a connection was
#    removed, and the removal finishes only then;
#  - the app's next run is not given the endpoint.
# Leaves the apps, the two registered connections and the runs in the project.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
state=$repo/run/local
out=${1:-$repo/run/connections-live-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$out"
manage=https://127.0.0.1:19090
target=fenders-live-target
api() { # METHOD PATH [JSON]
  curl -sS --fail-with-body --cacert "$state/pki/ca.pem" -X "$1" \
    -H "Authorization: Bearer $(cat "$state/control/operator.token")" \
    -H "Idempotency-Key: connections-$(date +%s%N)" -H 'Content-Type: application/json' \
    ${3:+-d "$3"} "$manage/v1$2"
}
upload() { # FILE
  local id
  id=$(curl -sS --fail-with-body --cacert "$state/pki/ca.pem" -X POST \
    -H "Authorization: Bearer $(cat "$state/control/operator.token")" \
    -H "Idempotency-Key: connections-artifact-$(date +%s%N)" -H 'Content-Type: application/wasm' \
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
start() { # APP
  api POST "$scope/apps/$1/runs" '{}' | jq -er '.run.id // .run_id // .resource_id // .id'
}
finish() { # APP RUN NAME: waits for the run's end, keeps the run and its output
  for _ in $(seq 90); do
    api GET "$scope/apps/$1/runs/$2" > "$out/$3.run.json"
    case $(jq -r .state "$out/$3.run.json") in succeeded|failed|cancelled) break ;; esac
    sleep 1
  done
  output "$1" "$2" "$3"
}
output() { # APP RUN NAME
  for _ in $(seq 10); do
    api GET "$scope/apps/$1/logs?run_id=$2" > "$out/$3.logs.json"
    [[ $(jq -r '.collection.complete // 0' "$out/$3.logs.json") == 1 || ${4:-} == now ]] && break
    sleep 1
  done
  jq -r '[.items[] | .bytes | @base64d] | join("")' "$out/$3.logs.json" > "$out/$3.txt"
}

scope=/workspaces/$(jq -er .tenant "$state/scope.json")/projects/$(jq -er .project "$state/scope.json")
tag=$(date +%H%M%S)
docker rm -f "$target" >/dev/null 2>&1 || true
docker run -d --name "$target" -e POSTGRES_PASSWORD=target --tmpfs /var/lib/postgresql/data \
  postgres:17-alpine >/dev/null
trap 'docker rm -f "$target" >/dev/null 2>&1 || true' EXIT
address=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$target")
until docker exec "$target" pg_isready -q -U postgres -h "$address"; do sleep 1; done

command=$(upload "$repo/build/node/example-command.wasm")
https=$(upload "$repo/build/node/example-public-https.wasm")
endpoint=$(api POST "$scope/connections" \
  "$(jq -n --arg n "live-db-$tag" --arg h "$address" '{name:$n,host:$h,port:5432}')" | jq -er .resource_id)
origin=$(api POST "$scope/connections" \
  "$(jq -n --arg n "live-web-$tag" '{name:$n,type:"https",origin:"https://example.com"}')" | jq -er .resource_id)
# What PostgreSQL answers one byte to: an SSLRequest.
probe=$(jq -n --arg denied "$address:5433" \
  '{TEST_MODE:"connect",TEST_CONNECT_SEND:"0000000804d2162f",TEST_CONNECT_DENIED:$denied}')

connected=$(deploy "connect-$tag" "$command" "$probe" "$(jq -n --arg c "$endpoint" '[{connection_id:$c}]')")
finish "$connected" "$(start "$connected")" connected

unconnected=$(deploy "unconnected-$tag" "$command" \
  "$(jq -n --arg h "$address" '{TEST_MODE:"connect",TEST_CONNECT_SEND:"0000000804d2162f",HOSTADDR:$h,PORT:"5432"}')" '[]')
finish "$unconnected" "$(start "$unconnected")" unconnected

web=$(deploy "web-$tag" "$https" '{"TEST_HTTPS_REQUESTS":"2","TEST_MEMORY_MIB":"'"${HTTPS_MEMORY_MIB:-4}"'"}' \
  "$(jq -n --arg c "$origin" '[{connection_id:$c}]')")
finish "$web" "$(start "$web")" web

# A run that connects once a second, and the connection taken from under it.
held=$(deploy "held-$tag" "$command" "$(jq '. + {TEST_CONNECT_ROUNDS:"120"} | del(.TEST_CONNECT_DENIED)' <<<"$probe")" \
  "$(jq -n --arg c "$endpoint" '[{connection_id:$c}]')")
run=$(start "$held")
for _ in $(seq 60); do
  output "$held" "$run" held-before now
  grep -q 'round 3 reply 4e' "$out/held-before.txt" && break
  sleep 1
done
revision=$(api GET "$scope/apps/$held/connections" | jq -er .revision)
removed_at=$(date +%s.%N)
removal=$(api PUT "$scope/apps/$held/connections" \
  "$(jq -n --argjson r "$revision" '{expected_revision:$r,connections:[]}')")
jq '{id,kind,state}' <<<"$removal" > "$out/removal-accepted.json"
api GET "$scope/apps/$held/connections" | jq '[.items[] | {name,state,reason}]' > "$out/removal-observed.json"
for _ in $(seq 300); do
  api GET "$scope/apps/$held/runs/$run" > "$out/held.run.json"
  case $(jq -r .state "$out/held.run.json") in succeeded|failed|cancelled) break ;; esac
  sleep 0.2
done
stopped_after=$(jq -n --arg a "$removed_at" --arg b "$(date +%s.%N)" '($b|tonumber)-($a|tonumber) | .*10 | round/10')
# A stopped run's output is not closed by its shim, so it is read as it stands.
sleep 2
output "$held" "$run" held now
for _ in $(seq 30); do
  api GET "$scope/operations/$(jq -er .id <<<"$removal")" > "$out/removal.json"
  [[ $(jq -r .state "$out/removal.json") != pending ]] && break
  sleep 1
done
rounds=$(grep -c 'reply 4e' "$out/held.txt" || true)
sleep 3
output "$held" "$run" held-later now
finish "$held" "$(start "$held")" after-removal

jq -n --arg address "$address" --arg stopped_after "$stopped_after" --arg rounds "$rounds" \
  --slurpfile connected "$out/connected.run.json" --rawfile connected_out "$out/connected.txt" \
  --slurpfile unconnected "$out/unconnected.run.json" --rawfile unconnected_out "$out/unconnected.txt" \
  --slurpfile web "$out/web.run.json" --rawfile web_out "$out/web.txt" \
  --slurpfile held "$out/held.run.json" --rawfile held_out "$out/held.txt" --rawfile held_later "$out/held-later.txt" \
  --slurpfile accepted "$out/removal-accepted.json" --slurpfile observed "$out/removal-observed.json" \
  --slurpfile removal "$out/removal.json" \
  --slurpfile after "$out/after-removal.run.json" --rawfile after_out "$out/after-removal.txt" '
  def lines($text; $pattern): [$text | split("\n")[] | select(test($pattern))];
  def run($r): {state: $r[0].state, exit_code: $r[0].exit_code, reason: $r[0].reason};
  {endpoint: ($address + ":5432"), origin: "https://example.com:443",
   with_the_endpoint: (run($connected) + {output: lines($connected_out; "^(connected|refused|connecting)")}),
   without_a_connection: (run($unconnected) + {output: lines($unconnected_out; "^(connected|refused|connecting)")}),
   with_the_origin: (run($web) + {output: lines($web_out; "^FENDERS_HTTPS")}),
   removal_while_running: {
     accepted: $accepted[0], connection_then: $observed[0],
     run: (run($held) + {diagnostic: $held[0].diagnostic.summary}),
     seconds_from_removal_to_the_runs_end: ($stopped_after|tonumber),
     connections_made_before_it_ended: ($rounds|tonumber),
     output_grew_after_it_ended: ($held_later != $held_out),
     operation: ($removal[0] | {state, error})},
   next_run_of_that_app: (run($after) + {output: lines($after_out; "connection did not set|^(connected|connecting)")})}
  | .passed = (
      .with_the_endpoint.state == "succeeded" and .with_the_endpoint.exit_code == 0
      and (.with_the_endpoint.output | any(test("^connected .* round 1 reply 4e$")))
      and (.with_the_endpoint.output | any(test("^refused .*:5433")))
      and .without_a_connection.state == "failed"
      and (.without_a_connection.output | any(test("^connecting to .* failed")))
      and (.without_a_connection.output | any(test("^connected")) | not)
      and .with_the_origin.state == "succeeded"
      and (.with_the_origin.output | any(test("sequence=2 status=200")))
      and .removal_while_running.accepted.state == "pending"
      and .removal_while_running.run.state == "cancelled"
      and .removal_while_running.run.reason == "connection-removed"
      and .removal_while_running.seconds_from_removal_to_the_runs_end < 10
      and .removal_while_running.connections_made_before_it_ended < 120
      and (.removal_while_running.output_grew_after_it_ended | not)
      and .removal_while_running.operation.state == "succeeded"
      and .next_run_of_that_app.state == "failed"
      and (.next_run_of_that_app.output | any(test("^connected")) | not))' | tee "$out/result.json"
jq -e .passed "$out/result.json" >/dev/null
