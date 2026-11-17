#!/usr/bin/env bash
# Run output end to end, against the local environment (scripts/local_env.sh up):
# deploys the command fixture as an app whose configuration holds a secret,
# in the mode that prints that secret on both streams and exits 1, runs it
# twice, and reads each run's output back through the customer API.
#
#   bash scripts/verify_output_live.sh [OUTPUT_DIR]
#
# Passes when both runs failed with exit 1, each run's output is complete and
# holds the program's lines on both streams with the secret masked, the
# secret's value is nowhere in what the API returned or the database stores,
# and none of the launcher's own lines (`guest exit`, its metrics) are in the
# output. Leaves the app, its secret and the runs in the project.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
state=$repo/run/local
out=${1:-$repo/run/output-live-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$out"
manage=https://127.0.0.1:19090
api() { # METHOD PATH [JSON]
  curl -sS --fail-with-body --cacert "$state/pki/ca.pem" -X "$1" \
    -H "Authorization: Bearer $(cat "$state/control/operator.token")" \
    -H "Idempotency-Key: output-$RANDOM-$RANDOM-$RANDOM" -H 'Content-Type: application/json' \
    ${3:+-d "$3"} "$manage/v1$2"
}
scope=/tenants/$(jq -er .tenant "$state/scope.json")/projects/$(jq -er .project "$state/scope.json")
name=output-$(date +%H%M%S)
secret_value=live-secret-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')

artifact=$(curl -sS --fail-with-body --cacert "$state/pki/ca.pem" -X POST \
  -H "Authorization: Bearer $(cat "$state/control/operator.token")" \
  -H "Idempotency-Key: output-artifact-$RANDOM-$RANDOM" -H 'Content-Type: application/wasm' \
  --data-binary @"$repo/build/node/example-command.wasm" "$manage/v1$scope/artifacts" | jq -er .id)
for _ in $(seq 90); do
  [[ $(api GET "$scope/artifacts/$artifact/inspection" | jq -r '.state // empty') == valid ]] && break
  sleep 1
done
secret=$(api POST "$scope/secrets" "$(jq -n --arg n "$name" --arg v "$secret_value" '{name:$n,value:$v}')" | jq -er .id)
api POST "$scope/apps/deploy" "$(jq -n --arg n "$name" --arg a "$artifact" --arg s "$secret" \
  '{name:$n,artifact_id:$a,triggers:{http:false,manual:true},
    configuration:{env:{TEST_MODE:"leak"},secret_env:{TEST_SECRET:$s}}}')" > "$out/deploy.json"
app=$(jq -er '.app.id // .app_id // .resource_id // .id' "$out/deploy.json")
for _ in $(seq 60); do
  [[ $(api GET "$scope/apps/$app" | jq -r .state) == ready ]] && break
  sleep 1
done

for attempt in 1 2; do
  run=$(api POST "$scope/apps/$app/runs" '{}' | jq -er '.run.id // .run_id // .resource_id // .id')
  for _ in $(seq 60); do
    api GET "$scope/apps/$app/runs/$run" > "$out/run-$attempt.json"
    case $(jq -r .state "$out/run-$attempt.json") in succeeded|failed|cancelled) break ;; esac
    sleep 1
  done
  for _ in $(seq 20); do
    api GET "$scope/apps/$app/logs?run_id=$run" > "$out/logs-$attempt.json"
    [[ $(jq -r '.collection.complete // 0' "$out/logs-$attempt.json") == 1 ]] && break
    sleep 1
  done
  for stream in stdout stderr; do
    jq -r --arg s "$stream" '[.items[] | select(.stream == $s) | .bytes | @base64d] | join("")' \
      "$out/logs-$attempt.json" > "$out/$stream-$attempt.txt"
  done
done

stored=$(docker exec fenders-local-pg psql -U postgres -d fenders -Atc \
  "SELECT count(*) FROM execution_log_records WHERE position(convert_to('$secret_value','UTF8') in payload) > 0")
leaked=$({ grep -l -- "$secret_value" "$out"/logs-*.json "$out"/std*.txt 2>/dev/null || true; } | wc -l)
jq -n --arg app "$name" --arg stored "$stored" --arg leaked "$leaked" \
  --slurpfile r1 "$out/run-1.json" --slurpfile r2 "$out/run-2.json" \
  --slurpfile l1 "$out/logs-1.json" --slurpfile l2 "$out/logs-2.json" \
  --rawfile o1 "$out/stdout-1.txt" --rawfile e1 "$out/stderr-1.txt" \
  --rawfile o2 "$out/stdout-2.txt" --rawfile e2 "$out/stderr-2.txt" '
  def run($r; $l; $o; $e): {
    state: $r[0].state, exit_code: $r[0].exit_code,
    collection: $l[0].collection,
    stdout: $o, stderr: $e,
    ok: ($r[0].state == "failed" and $r[0].exit_code == 1 and $l[0].collection.complete == 1
      and ($o | contains("the secret is [REDACTED]")) and ($e | contains("failing with [REDACTED]"))
      and (($o + $e) | test("guest exit|FENDERS_VMM_METRICS|unsupported syscall") | not))};
  {app: $app, first: run($r1; $l1; $o1; $e1), second: run($r2; $l2; $o2; $e2),
   secret_value_in_api_answers: ($leaked|tonumber), secret_value_in_stored_records: ($stored|tonumber)}
  | .passed = (.first.ok and .second.ok and .secret_value_in_api_answers == 0
      and .secret_value_in_stored_records == 0)' | tee "$out/result.json"
jq -e .passed "$out/result.json" >/dev/null
