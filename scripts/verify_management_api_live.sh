#!/usr/bin/env bash
# The management API as a client meets it, against the local environment
# (scripts/local_env.sh up): a real control plane over TLS and a real node.
# What the other scripts do not ask: the probes, the one vocabulary, lists by
# pages, what a refusal says, and what can be changed and removed.
#
#   bash scripts/verify_management_api_live.sh [OUTPUT_DIR]
#
# Passes when
#  - /healthz and /readyz answer with no credential, and nothing else does;
#  - a workspace is under /v1/workspaces and nowhere else, and is answered
#    with the fields the contract names;
#  - a wrong method, a body that is not JSON, and a malformed id are refused
#    as what they are (405 with Allow, 415, 400), each with a code;
#  - a component is inspected by the node; a secret is given another value
#    and a run started after has it, masked in its output;
#  - what something still names is not deleted (409 in_use), and what
#    nothing names is: a secret, an artifact, a project, an app by its
#    revision;
#  - lists are pages of items, continued by their cursor;
#  - the audit trail shows a key what its workspace's keys did, whole, and
#    what the operator did without its detail, and shows the operator all;
#  - a workspace is suspended, deleted, and is then no workspace.
#
# Leaves a project in the local workspace with one component in it (a
# component that was an app's code is kept), and a key it revokes at the end.
set -uo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
state=$repo/run/local
out=${1:-$repo/run/management-api-live-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$out"
manage=https://127.0.0.1:19090
build=$repo/build/node
ca=$state/pki/ca.pem
operator=$(cat "$state/control/operator.token")
tenant=$(jq -er .tenant "$state/scope.json")
node=$(jq -er .node "$state/scope.json")
pass=0
failed=()
# TOKEN METHOD PATH [BODY or @FILE] [CONTENT_TYPE]: the answer's body is
# left in $out/body and its headers in $out/headers; prints its status.
req() {
  local token=$1 method=$2 path=$3 body=${4-} type=${5-application/json}
  local args=(-sS --cacert "$ca" -o "$out/body" -D "$out/headers" -w '%{http_code}' -X "$method"
    -H "Idempotency-Key: management-$RANDOM-$RANDOM-$RANDOM")
  [[ -n $token ]] && args+=(-H "Authorization: Bearer $token")
  if [[ -n $body ]]; then
    if [[ $body == @* ]]; then args+=(-H "Content-Type: $type" --data-binary "$body")
    else args+=(-H "Content-Type: $type" -d "$body"); fi
  fi
  curl "${args[@]}" "$manage$path"
}
check() { # NAME GOT WANT
  if [[ $2 == "$3" ]]; then pass=$((pass + 1))
  else failed+=("$1: got '$2', want '$3'"); echo "FAIL $1: got '$2', want '$3'  $(head -c 300 "$out/body" 2>/dev/null)" >&2; fi
}
field() { jq -r "$1" "$out/body"; }

# Whether it is up, with no credential.
check "healthz without a credential" "$(req '' GET /healthz)" 200
check "healthz says ok" "$(field .status)" ok
check "readyz without a credential" "$(req '' GET /readyz)" 200
check "readyz says ready" "$(field .status)" ready
check "anything else wants a credential" "$(req '' GET /v1/workspaces)" 401
check "401 names bearer" "$(grep -i '^www-authenticate:' "$out/headers" | tr -d '\r' | cut -d' ' -f2)" Bearer

# One name: the old ones are no routes.
check "/v1/tenants is no route" "$(req "$operator" GET /v1/tenants)" 404
check "/v1/workspaces is a page" "$(req "$operator" GET /v1/workspaces)" 200
check "a page has items and next" "$(field 'has("items") and has("next")')" true
check "a workspace is read by itself" "$(req "$operator" GET "/v1/workspaces/$tenant")" 200
check "it is the local workspace" "$(field .name)" local
check "no row leaks" "$(field 'has("tenant_id") or has("display_name") or has("settings_revision")')" false

# A key for the workspace, as a product would issue one.
req "$operator" POST "/v1/workspaces/$tenant/api-keys" \
  '{"name":"management-live","permissions":["read","apps:write","runs:write","projects:write","connections:write","secrets:write"],"ttl_seconds":3600,"label":"user:management-live"}' >/dev/null
key=$(field .token); key_id=$(field .id)
check "a key is issued" "$(field .replayed)" false
check "me is the key's workspace" "$(req "$key" GET /v1/me >/dev/null; field .workspace_id)" "$tenant"
check "a key creates no workspace" "$(req "$key" POST /v1/workspaces '{}')" 403
check "that refusal has a code" "$(field .code)" permission_denied

# A project of its own, renamed.
w=/v1/workspaces/$tenant
check "a project is made" "$(req "$key" POST "$w/projects" "{\"name\":\"Live $RANDOM$RANDOM\"}")" 201
project=$(field .id)
check "its name is the one given" "$(field '.name | startswith("Live ")')" true
p=$w/projects/$project
check "a project is renamed" "$(req "$key" PATCH "$p" "{\"name\":\"Live renamed $RANDOM$RANDOM\"}")" 200
check "its slug follows" "$(field '.slug | startswith("live-renamed-")')" true

# Refusals a program can read.
check "a wrong method is 405" "$(req "$key" PUT "$w/projects" '{}')" 405
check "405 says which are taken" "$(grep -i '^allow:' "$out/headers" | tr -d '\r' | cut -d' ' -f2-)" "GET, HEAD, POST"
check "a form is 415" "$(req "$key" POST "$w/projects" '{"name":"A form"}' application/x-www-form-urlencoded)" 415
check "a malformed id in a body is 400" "$(req "$key" POST "$p/apps" '{"name":"bad","artifact_id":"nope"}')" 400

# A component, inspected by the real node.
check "a component is uploaded" "$(req "$key" POST "$p/artifacts" "@$build/example-command.wasm" application/wasm)" 201
artifact=$(field .id)
check "an upload said to be JSON is 415" "$(req "$key" POST "$p/artifacts" "@$build/example-command.wasm" application/json)" 415
for _ in $(seq 60); do
  req "$key" GET "$p/artifacts/$artifact/inspection" >/dev/null
  [[ $(field .state) == valid ]] && break
  sleep 1
done
check "the node inspects it" "$(field .state)" valid
check "a second, unused component is uploaded" "$(req "$key" POST "$p/artifacts" "@$build/example-async.wasm" application/wasm)" 201
unused=$(field .id)

# A secret, rotated before a run is given it.
check "a secret is made" "$(req "$key" POST "$p/secrets" '{"name":"token","value":"first-value-live"}')" 201
secret=$(field .id)
check "it is given another value" "$(req "$key" PUT "$p/secrets/$secret" '{"value":"second-value-live"}')" 200
check "the answer has no value" "$(grep -c value-live "$out/body")" 0

# An app that prints its secret, run on the real node.
req "$key" POST "$p/apps/deploy" "$(jq -n --arg a "$artifact" --arg s "$secret" \
  '{name:"management-live",artifact_id:$a,configuration:{env:{TEST_MODE:"leak"},secret_env:{TEST_SECRET:$s}},triggers:{manual:true,http:false}}')" > "$out/status"
check "an app is deployed" "$(cat "$out/status")" 201
app=$(field .resource_id)
check "an operation is what was asked" "$(field 'keys | join(",")')" "created,error,id,kind,resource_id,state,updated"
check "a run is taken" "$(req "$key" POST "$p/apps/$app/runs" '{}')" 202
run=$(field .resource_id)
for _ in $(seq 90); do
  req "$key" GET "$p/apps/$app/runs/$run" >/dev/null
  case $(field .state) in succeeded|failed|cancelled) break ;; esac
  sleep 1
done
state_of_run=$(field .state)
check "the run ends on the node" "$([[ $state_of_run == succeeded || $state_of_run == failed ]] && echo ended || echo "$state_of_run")" ended
for _ in $(seq 30); do
  req "$key" GET "$p/apps/$app/logs?run_id=$run" >/dev/null
  [[ $(field '.collection.complete // 0') == 1 ]] && break
  sleep 1
done
check "its output was collected" "$(field '(.items | length) > 0')" true
check "its output is a page read forwards" "$(req "$key" GET "$p/apps/$app/logs" >/dev/null; field 'has("items") and has("next") and has("has_more")')" true
check "the secret is masked in it" "$(jq -r '[.items[].bytes | @base64d] | join("")' "$out/body" | grep -c 'REDACTED' | sed 's/^[1-9][0-9]*$/masked/')" masked
check "the first value is nowhere in it" "$(jq -r '[.items[].bytes | @base64d] | join("")' "$out/body" | grep -c first-value-live)" 0
check "nor is the second, unmasked" "$(jq -r '[.items[].bytes | @base64d] | join("")' "$out/body" | grep -c second-value-live)" 0

# What is in use is not deleted; what is not, is.
check "a secret an app names is in use" "$(req "$key" DELETE "$p/secrets/$secret")" 409
check "and says so" "$(field .code)" in_use
check "a component that is an app's code is in use" "$(req "$key" DELETE "$p/artifacts/$artifact")" 409
check "an unused component is deleted" "$(req "$key" DELETE "$p/artifacts/$unused")" 200
check "it is gone" "$(req "$key" GET "$p/artifacts/$unused")" 404
check "a project that holds things is in use" "$(req "$key" DELETE "$p")" 409
check "an empty project is made" "$(req "$key" POST "$w/projects" "{\"name\":\"Empty $RANDOM$RANDOM\"}")" 201
empty=$(field .id)
check "and deleted" "$(req "$key" DELETE "$w/projects/$empty")" 200
check "it is no project after" "$(req "$key" GET "$w/projects/$empty/apps")" 404

# Lists, by pages.
check "operations are a page" "$(req "$key" GET "$p/operations?limit=1")" 200
check "of one, with more after" "$(field '(.items | length == 1) and (.next | type == "string")')" true
next=$(field .next)
check "the next page follows" "$(req "$key" GET "$p/operations?limit=1&before=$next")" 200
check "no request key is shown" "$(grep -c request_key "$out/body")" 0
check "a list takes nothing else" "$(req "$key" GET "$p/operations?offset=1")" 400
check "nodes are a page to the operator" "$(req "$operator" GET /v1/nodes >/dev/null; field '.items[0].name')" this-machine

# A deletion says its revision in its query.
req "$key" GET "$p/apps/$app" >/dev/null; revision=$(field .revision)
check "a deletion with a body is refused" "$(req "$key" DELETE "$p/apps/$app" '{"expected_revision":1}')" 400
check "an app is deleted by its revision" "$(req "$key" DELETE "$p/apps/$app?expected_revision=$revision" | grep -cE '^20[02]$')" 1
for _ in $(seq 30); do
  [[ $(req "$key" DELETE "$p/secrets/$secret") == 200 ]] && break
  sleep 1
done
check "its secret may then go" "$(req "$key" GET "$p/secrets/$secret")" 404

# The trail of all that, as the key and as the operator read it.
check "the key reads its workspace's trail" "$(req "$key" GET "$w/audit?actor_label=user:management-live&limit=100")" 200
check "what it did is there, with its label" "$(field "[.items[] | select(.action==\"secret.rotate\" and .actor_label==\"user:management-live\" and .actor==\"$key_id\")] | length")" 1
check "and in its project" "$(field "[.items[] | select(.action==\"secret.rotate\" and .actor==\"$key_id\") | .project_id] | .[0]")" "$project"
req "$key" GET "$w/audit?action=api-key.create&limit=1" >/dev/null
check "what the operator did is the operator's" "$(field '.items[0] | [.actor, (.detail|tostring)] | join(" ")')" "operator null"
req "$operator" GET "$w/audit?action=api-key.create&limit=1" >/dev/null
check "the operator reads it whole" "$(field '.items[0].detail.label')" user:management-live

# A workspace that leaves: suspended, then deleted.
req "$operator" POST /v1/workspaces '{"name":"leaving","allowance":{"cpu_percent":100,"memory_mib":512,"storage_bytes":1048576,"instances":1,"transfer_bytes":1048576}}' >/dev/null
leaving=$(field .id)
check "a workspace that runs things is not deleted" "$(req "$operator" DELETE "/v1/workspaces/$leaving")" 409
check "it is suspended" "$(req "$operator" POST "/v1/workspaces/$leaving/lifecycle" '{"action":"suspend","reason":"Left","expected_revision":1}' >/dev/null; field .status)" suspended
check "and then deleted" "$(req "$operator" DELETE "/v1/workspaces/$leaving")" 200
check "it is no workspace after" "$(req "$operator" GET "/v1/workspaces/$leaving")" 404
check "nor is anything under it" "$(req "$operator" GET "/v1/workspaces/$leaving/audit")" 404

# The node serves: it is not to be deleted.
check "a serving node is in use" "$(req "$operator" DELETE "/v1/nodes/$node")" 409
check "the contract is served" "$(req '' GET /api/openapi.json)" 200
check "and lists the new routes" "$(jq -r '[.paths | has("/healthz"), has("/workspaces/{workspace}/audit")] | all' "$out/body")" true


# The key this used opens nothing after.
check "the key is revoked" "$(req "$operator" DELETE "$w/api-keys/$key_id")" 200
check "and opens nothing" "$(req "$key" GET /v1/me)" 401

rm -f "$out/body" "$out/headers" "$out/status"
jq -n --argjson passed_checks "$pass" --args '{passed: (($ARGS.positional | length) == 0), checks_passed: $passed_checks, failed: $ARGS.positional}' \
  ${failed[@]+"${failed[@]}"} | tee "$out/result.json"
jq -e .passed "$out/result.json" >/dev/null
