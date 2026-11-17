#!/usr/bin/env bash
# Fenders built into another product, end to end on this host, with no console
# and no sign-in provider: the host product holds the operator credential,
# creates two tenants and a scoped API key for each, and each tenant's key
# uploads a component, deploys it and runs it on a real fenders-node, shim
# and KVM guest. Then the boundaries: neither key sees the other tenant, a
# tenant key cannot call an operator endpoint, and no console is served.
#
#   bash scripts/verify_embedding_live.sh [OUTPUT_DIR]
#
# Needs: Linux x86-64 with /dev/kvm, cgroup v2, passwordless sudo, Docker (for a
# disposable PostgreSQL 17), curl, jq, and `scripts/build_node.sh` already run.
# It creates OUTPUT_DIR, /var/lib/fenders-embedding-live (a copy of the node
# bundle and the node's state), one cgroup and one container; all but
# OUTPUT_DIR's logs and result.json are removed on exit.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$repo/run/embedding-live-$(date +%Y%m%d-%H%M%S)}
build=$repo/build/node
bin=$repo/target/release
for file in "$build/fenders-node" "$build/fenders-shim" "$build/launch" "$build/runtime.elf" \
  "$build/example-command.wasm" "$bin/fenders-control-plane" "$bin/fenders-pki"; do
  [[ -f $file ]] || { echo "missing $file: run scripts/build_node.sh" >&2; exit 2; }
done
[[ -c /dev/kvm ]] && sudo -n true
mkdir -p "$out"
out=$(cd "$out" && pwd)
pg=fenders-embedding-live
cgroup=/sys/fs/cgroup/fenders-embedding-live
# The compiler and the runs drop root's privileges, so the bundle and the
# node's state must be reachable without them: not under a private home.
stage=/var/lib/fenders-embedding-live
base=19390
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
until docker exec "$pg" pg_isready -q -U postgres; do sleep 1; done
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

as() { # TOKEN METHOD PATH [JSON]  -> body, then the status on a last line
  curl -sS --cacert "$out/pki/ca.pem" -X "$2" -H "Authorization: Bearer $1" \
    -H "Idempotency-Key: live-$RANDOM-$RANDOM-$RANDOM" -H 'Content-Type: application/json' \
    ${4:+-d "$4"} -w '\n%{http_code}' "$manage/v1$3"
}
status() { tail -n 1; }
ok() { # as ... | ok  -> the body, failing unless 2xx
  local reply; reply=$(cat)
  [[ $(tail -n 1 <<<"$reply") == 2* ]] || { echo "request failed: $reply" >&2; exit 1; }
  sed '$d' <<<"$reply"
}

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
  > /dev/null 2> "$out/node.log" &
node_pid=$!

# What the host product does for each of its customers, as the operator.
allowance='{"cpu_percent":200,"memory_mib":1024,"storage_bytes":1073741824,"instances":2,"transfer_bytes":1073741824}'
declare -A tenant project key run_state exit_code
for name in alpha beta; do
  tenant[$name]=$(api POST /tenants "$(jq -n --arg n "$name" --argjson a "$allowance" '{name:$n,allowance:$a}')" | jq -er .id)
  project[$name]=$(api GET "/tenants/${tenant[$name]}/projects" | jq -er '.[0].id')
  key[$name]=$(api POST "/tenants/${tenant[$name]}/api-keys" \
    '{"name":"product","permissions":["read","apps:write","runs:write"],"ttl_seconds":3600}' | jq -er .token)
done

# What each customer's key does, through the tenant API alone.
for name in alpha beta; do
  scope=/workspaces/${tenant[$name]}/projects/${project[$name]}
  artifact=$(curl -sS --fail-with-body --cacert "$out/pki/ca.pem" -X POST -H "Authorization: Bearer ${key[$name]}" \
    -H "Idempotency-Key: live-artifact-$name-$RANDOM" -H 'Content-Type: application/wasm' \
    --data-binary @"$build/example-command.wasm" "$manage/v1$scope/artifacts" | jq -er .id)
  for _ in $(seq 90); do
    state=$(as "${key[$name]}" GET "$scope/artifacts/$artifact/inspection" | ok | jq -r '.state // empty')
    [[ $state == valid ]] && break
    [[ $state == invalid ]] && { echo "component rejected" >&2; exit 1; }
    sleep 1
  done
  [[ $state == valid ]] || { echo "inspection did not finish (state: $state)" >&2; tail -20 "$out/node.log" >&2; exit 1; }
  as "${key[$name]}" POST "$scope/apps/deploy" "$(jq -n --arg a "$artifact" --arg n "$name-app" \
    '{name:$n,artifact_id:$a,triggers:{http:false,manual:true}}')" | ok > "$out/$name-deploy.json"
  app=$(jq -er '.app.id // .app_id // .resource_id // .id' "$out/$name-deploy.json")
  for _ in $(seq 60); do
    [[ $(as "${key[$name]}" GET "$scope/apps/$app" | ok | jq -r .state) == ready ]] && break
    sleep 1
  done
  run=$(as "${key[$name]}" POST "$scope/apps/$app/runs" '{}' | ok | jq -er '.run.id // .run_id // .resource_id // .id')
  for _ in $(seq 60); do
    as "${key[$name]}" GET "$scope/apps/$app/runs/$run" | ok > "$out/$name-run.json"
    run_state[$name]=$(jq -r .state "$out/$name-run.json")
    case ${run_state[$name]} in succeeded|failed|cancelled) break ;; esac
    sleep 1
  done
  exit_code[$name]=$(jq -r '.exit_code // empty' "$out/$name-run.json")
  eval "app_$name=$app"
done

# The boundaries.
other=/workspaces/${tenant[beta]}/projects/${project[beta]}
cross_read=$(as "${key[alpha]}" GET "$other/apps" | status)
cross_app=$(as "${key[alpha]}" GET "$other/apps/$app_beta" | status)
cross_run=$(as "${key[alpha]}" POST "$other/apps/$app_beta/runs" '{}' | status)
cross_list=$(as "${key[alpha]}" GET /workspaces | ok | jq -c '[.[].id]')
operator_tenants=$(as "${key[alpha]}" POST /tenants "$(jq -n --argjson a "$allowance" '{name:"gamma",allowance:$a}')" | status)
operator_nodes=$(as "${key[alpha]}" GET /nodes | status)
no_credential=$(curl -sS --cacert "$out/pki/ca.pem" -o /dev/null -w '%{http_code}' "$manage/v1/workspaces")
console=$(curl -sS --cacert "$out/pki/ca.pem" -o /dev/null -w '%{http_code}' "$manage/console/")
root=$(curl -sS --cacert "$out/pki/ca.pem" -o /dev/null -w '%{http_code}' "$manage/")
contract=$(curl -sS --cacert "$out/pki/ca.pem" -o /dev/null -w '%{http_code}' "$manage/api/openapi.json")
# A key that was revoked stops working.
key_id=$(api GET "/tenants/${tenant[beta]}/api-keys" | jq -er '.items[0].id')
api DELETE "/tenants/${tenant[beta]}/api-keys/$key_id" > /dev/null
revoked=$(as "${key[beta]}" GET /workspaces | status)

jq -n --arg alpha "${run_state[alpha]}" --arg alpha_exit "${exit_code[alpha]}" \
  --arg beta "${run_state[beta]}" --arg beta_exit "${exit_code[beta]}" \
  --arg own "${tenant[alpha]}" --argjson cross_list "$cross_list" \
  --arg cross_read "$cross_read" --arg cross_app "$cross_app" --arg cross_run "$cross_run" \
  --arg operator_tenants "$operator_tenants" --arg operator_nodes "$operator_nodes" \
  --arg no_credential "$no_credential" --arg revoked "$revoked" \
  --arg console "$console" --arg root "$root" --arg contract "$contract" \
  --arg started "$(grep -c 'agent: run started' "$out/node.log" || true)" \
  '{passed: ($alpha == "succeeded" and $alpha_exit == "0" and $beta == "succeeded" and $beta_exit == "0"
      and $cross_list == [$own] and $cross_read == "404" and $cross_app == "404" and $cross_run == "404"
      and $operator_tenants == "403" and $operator_nodes == "403" and $no_credential == "401"
      and $revoked == "401" and $console != "200" and $root != "200" and $contract == "200"),
    runs: {alpha: {state: $alpha, exit_code: $alpha_exit}, beta: {state: $beta, exit_code: $beta_exit}},
    tenant_key: {workspaces_listed: $cross_list, own_workspace: $own,
      other_tenant_apps: $cross_read, other_tenant_app: $cross_app, other_tenant_run: $cross_run,
      create_tenant: $operator_tenants, list_nodes: $operator_nodes},
    no_credential: $no_credential, revoked_key: $revoked,
    served: {console: $console, root: $root, api_contract: $contract},
    node: {runs_started: ($started|tonumber)}}' | tee "$out/result.json"
[[ $(jq -r .passed "$out/result.json") == true ]]
