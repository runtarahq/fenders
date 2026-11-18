# Fixing the management API's inconsistencies

A plan, and a record of how far it has got: phase 1 is done, the rest is
not. It answers an audit of the
management API (the operator's routes and the workspace API) made on
2026-11-18 by reading `crates/fenders-control-plane` and probing a running
control plane with no node attached. The node protocol, the run channel and
the gateway were not audited and are not changed by this plan.

The audit found the boundaries sound: tenant isolation, permissions,
revocation, suspension, body limits and the idempotency of the workspace
routes all behaved as documented. What follows is what did not, and the
order to fix it in.

Delete this file when its last phase lands; what remains true belongs in
[STATUS.md](STATUS.md) and [EMBEDDING-API.md](EMBEDDING-API.md).

## Decisions

Made on 2026-11-18; the phases below are written to them.

| # | Decision | Decided |
|---|---|---|
| D1 | Which word is the API's: `tenants` or `workspaces`, `external-endpoints` or `connections` | `workspaces` and `connections` everywhere, the operator's routes included. They are what the contract already says. The database keeps its names. |
| D2 | Whether breaking changes are made in place under `/v1` | Yes. Nothing is released, and `STATUS.md` says pre-1.0. Make them in one phase (4), list them in one place, and declare `/v1` stable only after. |
| D3 | The one shape of a list | `{"items": […], "next": CURSOR or null}` for every list, with `limit` (1 to 100) and the cursor passed back as `before`. Extra fields beside those two are allowed. Logs keep `after`, because they are read forwards. |
| D4 | Whether quota exhaustion stays `429` | No: `429` only for rates, with `Retry-After`. An exhausted allowance or metadata limit becomes `409` with its own `code`. |
| D5 | What `code` is for | A stable, machine-readable reason, more specific than the status. See phase 2. |
| D6 | How much of phase 5 (new routes) is wanted before `/v1` is called stable | The health route and the audit read; the deletes can follow. |

## Phase 1: behaviour that contradicts the documents

**Done**, one commit an item (three for 1.1), each with its test in
`tests/cases/customer_api.rs` (1.2 in `workspace_lifecycle.rs`, 1.5 in
`accounting_retention.rs`). Where what was built differs from what is
written below:

- 1.1: a retry of `PUT /v1/public-egress-policy` is answered with the
  policy as it stands, not with a stored copy of the first answer. Schema
  migration 9 makes a receipt's tenant optional.
- 1.3: a key that no request could carry is `404`, as a key nothing was made
  with is. Saying in the contract that the key is percent-encoded waits for
  3.1, which adds these routes to it.
- 1.4: the first answer says `"replayed": false` as well.

No route changes shape.

### 1.1 The operator's changes ignore `Idempotency-Key`

`POST /v1/tenants` twice with one key makes two tenants; a retried
`POST /v1/nodes` is answered `409`. `EMBEDDING-API.md` says every change
takes the header and a retry returns the original result.

- `api.rs` passes no key to `create_tenant`, `register_node`, `node_mode`,
  `update_allowance`, `update_http_limits` or `activate_public_egress`.
  Pass it to all six.
- Reuse `operator_request_receipts` (`workspace_lifecycle.rs`): it is keyed
  by `(actor, request_key)` already. Its `tenant_id` is `NOT NULL` and a node
  has none: make the column nullable in `schema_migrations.rs`.
- Move the receipt read and write out of `operator_workspace_action` into two
  functions beside `customer_api::receipt`, and call them from all seven.
- Require the header on the two `POST`s, as the workspace routes do. On the
  `PATCH`es and the `PUT` accept it and honour it, but do not require it:
  they are idempotent as written.
- Tenant names stay as they are: not unique, a label and nothing more.
  What identifies a tenant is its id, which is unique already
  (`tenants_pkey`) and made by the control plane. So nothing but the
  receipt stops a retry from making a second tenant; no constraint is
  added. Say in `EMBEDDING-API.md` section 4 that two tenants may share a
  name and that a caller keeps the id.

### 1.2 Suspending a workspace: the key is in the body, and must be 32 hex digits

`POST /v1/tenants/T/lifecycle` takes `request_key` in its body and passes it
to `identity()`, so any other key is answered `404 resource not found`.

- Take the key from the `Idempotency-Key` header, 1 to 128 characters, like
  every other route. Accept `request_key` in the body for one release, then
  remove it (it is `deny_unknown_fields`, so removal is a break: do it in
  phase 4).
- Fix the example in `EMBEDDING-API.md` section 4.

### 1.3 Looking up a submission works only for a 32-hex key

`app_submission`, `app_action_submission` (`apps.rs`) and
`endpoint_submission` (`external_endpoints.rs`) call `identity(key)`. The
header accepts any 1 to 128 characters, so a request made with the key `d1`
cannot be found again.

- Replace `identity(key)` with the same length check `receipt` makes.
- A key is a path segment here: say in the contract that it must be
  percent-encoded, and test one that contains `/` and one that contains a
  space.

### 1.4 A retried key creation returns no token

By design the token is not stored, so the replay of
`POST /v1/tenants/T/api-keys` is the row without `token`. A caller that lost
the first answer holds a live key nobody can use, and cannot tell from the
answer.

- Keep not storing it. Answer the replay `200` (not `201`) with
  `"token": null` and `"replayed": true`, and document that the caller then
  revokes the key by its `id` and issues another.
- Document it in `EMBEDDING-API.md` section 4 and the contract (phase 3.2).

### 1.5 Usage history pages with `next_before`

`usage.rs:206` returns `next_before`; the contract's `Page` requires `next`.

- Return `next`. Keep `next_before` beside it until phase 4.

## Phase 2: errors

One change to `error.rs` and its callers; no success response changes.

### 2.1 `code` says no more than the status

`Error::code()` is derived from the status, so a client learns nothing from
it, and `408` is reported as `internal_error`.

- Give `Error` an optional `code: &'static str` that overrides the default,
  set with a builder (`.coded("quota_exhausted")`), so the hundreds of
  existing call sites stay as they are.
- Add the missing defaults: `408 request_timeout`, `405 method_not_allowed`,
  `502 bad_gateway`, `504 gateway_timeout`.
- First specific codes, each where its error is made today:

| Code | Status | Today |
|---|---|---|
| `idempotency_key_required` | 400 | `invalid_request` |
| `idempotency_key_reused` | 409 | `conflict` |
| `revision_conflict` | 409 | `conflict` |
| `already_exists` | 409 | `conflict` |
| `not_validated` | 409 | `conflict` (component not yet inspected) |
| `workspace_suspended` | 403 | `forbidden` |
| `permission_denied` | 403 | `forbidden` |
| `quota_exhausted` | 409 (D4) | `rate_limited`, 429 |
| `rate_limited` | 429 | the same, now only for rates |

- List every code in the contract as an enum of `Error.code`.

### 2.2 `429` means two things, and never says when to retry

`db::quota` (storage allowance, metadata limits, instance allowance) and the
mutation rate both answer `429`.

- `db::quota` becomes `409 quota_exhausted` (D4). Check each caller: one that
  is a rate stays `429`.
- The mutation rate (`api.rs`, `MUTATIONS_A_MINUTE`) and "too many uploads in
  progress" answer with `Retry-After`. `ingress::Rates::admit` returns a
  `bool`: make it return the seconds until the window turns.

### 2.3 Smaller status fixes

- `401` carries `WWW-Authenticate: Bearer`.
- A known path with a method it does not take is `405` with `Allow`, to
  operator and key alike. Today it is `404` to the operator and `403` to a
  key. Build the answer from `customer_api::permission` and `operators`, so
  that a key still learns nothing of a path it could not use: `405` only
  where some method on that path is one the caller may make.
- `HEAD` is answered as `GET` without a body wherever `GET` is allowed.
- A JSON route given another `Content-Type` is `415`; an upload that is not
  `application/wasm` is `415`. Today neither is looked at.
- A malformed id in a path stays `404`: it names nothing. A malformed id in
  a body becomes `400` (`value::id` returns `missing` today).

## Phase 3: the contract

`static/api/openapi.json` is written by hand. This phase makes it complete
and makes tests hold it to the code.

### 3.1 Routes the contract does not have

Add, with request and response schemas:

- `DELETE …/apps/{app}`. Note that it takes a body (`expected_revision`);
  see 4.5.
- `POST …/apps/{app}/http-sample`
- `GET …/app-submissions/{key}`, `GET …/apps/{app}/submissions/{key}`,
  `GET …/endpoint-submissions/{key}`

### 3.2 The operator's routes

Add them all (the table in `EMBEDDING-API.md`), under a second security
scheme `operator`, tagged `operator`. Remove the "not yet in the contract"
lines from `STATUS.md` and `EMBEDDING-API.md` in the same change.

### 3.3 Real response schemas

Nearly every response is `Record`, an object of anything. Replace it with a
schema per resource: `Workspace`, `Project`, `Artifact`, `Inspection`, `App`,
`Version`, `Release`, `Run`, `Triggers`, `AppConnections`, `Connection`,
`Secret`, `Operation`, `Usage`, `UsagePeriod`, `LogPage`, `Event`, `AppSizes`,
`HttpStatus`, `HttpSample`, `ApiKey`, `Node`, `EgressPolicy`, `Status`, `Me`.
Each lists the fields phase 4.3 keeps, with `additionalProperties: true` so
that adding a field is never a break.

Write these after 4.3 is designed, or they will be written twice. If phase 4
is deferred, write them for the responses as they are.

### 3.4 Smaller corrections

- `info.version` is the crate's version, not `1.0.0`. A test compares it to
  `CARGO_PKG_VERSION`.
- `202` means the operation's `state` is `pending`. Creating a connection
  and cancelling a run answer `202` with `succeeded`: answer `200` then, as
  the app routes do through the check at the end of `dispatch_inner`. Make
  that check the only place the choice is made, and drop the fixed
  `ACCEPTED`s above it.
- Path parameters are written out in every operation: move them to
  `components/parameters`.
- Document `Retry-After`, `WWW-Authenticate` and the error codes.

### 3.5 Tests that hold the contract to the code

- The test `documented_routes_are_reachable_through_the_customer_boundary`
  (`customer_api.rs`) checks contract ⊆ router. Add the converse. `permission`
  and `operators` are `match`es and cannot be listed, so first turn each into
  a table (`&[(method, pattern, permission)]`) that the `match` is replaced
  by; the test then walks the table.
- A response test: for each documented `GET`, and each mutation the suite
  already makes, validate the body against its schema (the `jsonschema`
  crate, as a dev-dependency). Put it in `tests/cases/customer_api.rs`,
  which already drives every route.

## Phase 4: one shape (the breaking changes)

Everything here changes what a client sees. Do it as one change set, to
D1 to D3, and list each break in `STATUS.md` under a heading of its own.

### 4.1 One vocabulary (D1)

- The operator's routes move under `/v1/workspaces/W/…`: `api-keys`,
  `lifecycle`, `http-limits`, and `POST`/`PATCH` on the workspace itself.
- `/v1/tenants/…` and `…/external-endpoints` are no longer answered. Today
  they are aliases, and not consistently: a key asking for
  `/v1/tenants/T/projects/P/connections` gets `403`, and the operator's
  routes exist under one prefix only. `dispatch_inner` rewrites the path
  before matching; invert that so the match arms are written in the public
  names and nothing is rewritten.
- In responses, `tenant_id` becomes `workspace_id`. This falls out of 4.3.
- `fendersctl`, the `scripts/verify_*_live.sh` harnesses, `local_env.sh` and
  the two embedding guides use the old paths: change them together.

### 4.2 One list shape (D3)

| Today | Lists |
|---|---|
| A bare array | workspaces, projects, artifacts, secrets, connections, operations, nodes |
| `{items}` | API keys |
| `{items, next}` | versions, releases, runs |
| `{items, next, offset, total}` | apps |
| `{items, next_before}` | usage history |
| `{items, next, has_more}`, read with `after` | logs |

- All become `{items, next}`. `Store::resources` (`store.rs`) stops at 1000
  rows without saying so: give it `before` and `limit`, ordered by
  `(created, id)`. Do the same for workspaces, projects, nodes and API keys.
- A cursor is opaque. Versions page by a number and runs by a timestamp
  today; encode whatever each needs as a string and document only "pass back
  what you were given".
- Drop `offset` from apps and `has_more` from logs (`next` is null when there
  is no more).

### 4.3 Responses are projections, not rows

Tenants, projects, artifacts, nodes, operations and the egress policy are
returned with `to_jsonb(row)` or `RETURNING *`. A response then carries
whatever the table has (`singleton`, `settings_revision`, `request_hash`,
`target_revision`, `retired_at`), and a migration changes the API.

- One projection function per resource (as `api_keys` and `secrets` already
  have with `jsonb_build_object`), used by the read, the list and every
  mutation that returns the resource.
- `Operation` loses `request_hash`, `request_key`, `target_revision` and the
  scope ids. `request_key` matters most: `GET …/operations` shows every
  caller's idempotency keys to any key with `read`.
- `Project`: the request's `name` comes back as `display_name` and `name`
  holds the slug. Return `name` as given and `slug` beside it; drop
  `display_name`. The same for a workspace.
- A cancelled run's operation has `kind: "stop"` and an execution id as its
  `resource_id`, which no route reads. Return `kind: "cancel-run"` and the
  run's id (`cancel_app_run`, `app_runtime.rs:793`).

### 4.4 What a console would say

`app_diagnostics.rs` writes for a screen: `actions: [{label: "View lifecycle
events", target: "events"}]`, and "contact support if this persists".

- Keep `summary`, `detail` and a stable `reason`. Remove `actions`, and the
  sentences that speak of support: whoever embeds Fenders decides what its
  users are told.
- Reword the comments in `api.rs` and `customer_api.rs` that still speak of
  a console the control plane serves.

### 4.5 Revisions and bodies

- `DELETE …/apps/{app}` requires a JSON body. Take `expected_revision` as a
  query parameter, or the revision in `If-Match`; refuse a body.
- An app has a `revision`, its triggers have another, and a workspace has
  `lifecycle_revision`, `allowance_revision` and `settings_revision`. Each
  route checks a different one and only the code says which. Either document
  each beside its route in the contract, or, better, return the one to send
  back in every response that route's caller reads first (`GET …/triggers`
  already does).
- `PATCH` on a workspace takes no expected revision though
  `allowance_revision` exists. Accept an optional one.
- Remove `request_key` from the lifecycle body (1.2).

## Phase 5: what is missing

Additions only. Order by D6.

| Route | Why | Notes |
|---|---|---|
| `GET /healthz`, `GET /readyz` | Nothing can be probed without the operator's token: `/health` is `401` | No credential. `healthz` is the process; `readyz` also reads the database and the recovery barrier. Answer nothing but a status. |
| `GET /v1/workspaces/W/audit` | The guide calls the audit trail the way actions lead back to users, and no route reads it | The operator reads any workspace's; a key with `read` reads its own workspace's, and another's is `404`. Paged; filter by `actor_label`, `action`, time. See below. |
| `GET /v1/workspaces/W` | A workspace is readable only by listing | |
| `DELETE …/secrets/S`, `PUT …/secrets/S` | A secret cannot be removed or rotated | Refuse a delete while a release names it; say when a rotation reaches running executions. |
| `DELETE …/artifacts/A` | Storage is charged and only retention frees it | Refuse while a version names it. |
| `DELETE …/projects/P`, `PATCH …/projects/P` | 256 a workspace, and none can go | Only when empty. |
| `DELETE /v1/workspaces/W` | A customer that leaves stays for good | Only when suspended; decide what of usage and audit is kept. |
| `DELETE /v1/nodes/N` | A node can be disabled, never removed | Only when drained. |

Each needs its permission in `customer_api.rs`, its row in the contract, an
audit record and a case in `tests/cases/customer_api.rs`.

### The audit read, for a key

A tenant's key reads its own workspace's audit records. Three things follow
from what the table holds:

- What the operator wrote for itself stays the operator's. `GET /workspaces`
  already keeps `lifecycle_reason` from a key; the audit read does the same
  for the reason of a suspension and for records whose actor is the operator
  or the control plane (`audit_system`): a key sees that the action happened
  and when, not the operator's `detail`.
- `actor` is a credential's id. A key sees the ids and labels of its own
  workspace's keys, which it cannot otherwise list. That is intended: the
  label is how a host product's users are told apart.
- An audit record has a workspace and no project. A key scoped to one project
  would read what was done in the others, so it is refused (`404`, as for
  anything outside its project) until records carry a project. Adding the
  column, and filling it where the action has one, is part of this route's
  change.

## Not in this plan

- The single unscoped operator credential, the in-memory rate counters and
  the 30-day key lifetime: known limits, in `STATUS.md`.
- Every mutation takes one advisory lock (`store.rs`,
  `pg_advisory_xact_lock`), so changes across all workspaces are made one at
  a time. It bounds throughput and deserves measuring, but it is not an
  inconsistency of the API.
- The gateway's and the node routes' errors are `{"error": …}` without
  `code` or `request_id`. They are other surfaces with other callers.

## Order and size

| Phase | Breaks clients | Depends on | Rough size |
|---|---|---|---|
| 1 Contradictions | No | Nothing | Small: five fixes, one migration |
| 2 Errors | Codes change; `429` to `409` for quota | D4, D5 | Small |
| 3 Contract | No | 4.3 for the schemas (3.3) | Medium: mostly the schemas |
| 4 One shape | Yes | D1, D2, D3 | Large: every path and list |
| 5 Missing routes | No | D6 | Medium, and divisible |

Phases 1 and 2 can land at once. 3.1, 3.2, 3.4 and 3.5 can follow without
waiting for phase 4; 3.3 should be written with 4.3.

## How each phase is shown to hold

- `make check` and `make test` (the control-plane suite, with
  `--test-threads=4`).
- The two contract tests of 3.5, once they exist, for every later phase.
- `scripts/verify_embedding_live.sh` after phases 1, 2 and 4: it asserts the
  status codes at the boundaries (`401`, `403`, `404`) that phases 2 and 4
  touch.
- For phase 1, the probes that found each item, as tests: one key twice on
  `POST /v1/tenants` yields one tenant; a suspension with a key that is not
  hex succeeds; a submission made with the key `d1` is found again; a
  replayed key creation says it was replayed; usage history has `next`.
- Update `STATUS.md` and `EMBEDDING-API.md` in the change that makes each of
  their statements true, as `STATUS.md` asks.
