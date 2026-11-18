# Embedding the API: multi-tenant execution behind your product

Use this when you want Fenders to hold the tenants, quotas, artifacts, apps
and runs, and your product to drive it over HTTP. There is no console and no
sign-in provider to set up: your product holds one **operator credential**,
creates a tenant for each of its customers, and gives each a **tenant key**
(or keeps the keys itself and calls on its customers' behalf).

Everything on this page is run end to end, with two tenants, by
`scripts/verify_embedding_live.sh`. When this page and that script differ,
the script is right.

## The pieces

| Process | Where | Listens |
|---|---|---|
| `fenders-control-plane` | Any machine that reaches PostgreSQL 17 | The management API; an mTLS listener for nodes; the gateway for HTTP apps; the run channel for shims |
| `fenders-node` | Each Linux x86-64 KVM machine that runs code | One mTLS port for its control plane |

```sh
make build-node      # build/node: fenders-node, fenders-shim, launch, runtime.elf, compile
                     # target/release: fenders-control-plane, fenders-pki
```

## 1. Certificates

One CA signs the control plane and every node, and each pins the other.
`fenders-pki` makes a CA and identities and prints their pins:

```sh
target/release/fenders-pki --output pki \
  --identity control=control.internal --identity node=node-1.internal > pins.json
```

Keep the CA key off the hosts that serve.

## 2. The control plane

```sh
FENDERS_DATABASE_URL='postgresql://USER:PASSWORD@HOST/fenders?sslmode=verify-full&sslrootcert=/etc/fenders/db-ca.pem' \
target/release/fenders-control-plane --state /var/lib/fenders/control \
  --host 0.0.0.0 --port 9090 --internal-port 9091 --gateway-port 9092 \
  --run-channel-port 9093 --run-channel-endpoint https://control.internal:9093 \
  --domain apps.example.com \
  --ca pki/ca.pem --cert pki/control.pem --key pki/control.key
```

A database on another host must say in its URL how the connection is secured:
`sslmode=verify-full` with the CA that signed the server's certificate, or a
weaker `sslmode` chosen knowingly. Without one the control plane and its
tools refuse to start, because a PostgreSQL client left to itself tries TLS,
verifies nothing and falls back to none. A database on this host (loopback or
a socket directory) needs no `sslmode`.

- `--run-channel-endpoint` is the address **nodes** use to reach the run
  channel. Without it no run starts.
- `--domain` is the parent of HTTP apps' host names; the gateway on
  `--gateway-port` serves them.
- At first start the control plane migrates its schema and writes the
  operator credential to `STATE/operator.token`. That file is the only copy.
- `deploy/systemd/` has a unit and its [guide](../deploy/systemd/README.md).

The management API is `https://HOST:9090/v1`. Every call takes
`Authorization: Bearer TOKEN`; every change takes an `Idempotency-Key`
header, and a retry with the same key returns the original result.

## 3. A node

Register it, as the operator, with the pin of its certificate:

```sh
curl --cacert pki/ca.pem -H "Authorization: Bearer $OPERATOR" \
  -H 'Idempotency-Key: node-1' -H 'Content-Type: application/json' \
  https://control.internal:9090/v1/nodes -d '{
    "name": "node-1", "cert_sha256": "PIN OF node FROM pins.json",
    "endpoint": "https://node-1.internal:9443",
    "backend": "wasm", "architecture": "x86_64", "runtime": "wasmtime-50.0.0-fenders-v1",
    "cpu_percent": 200, "memory_mib": 1024, "instances": 4}'
```

Then start it, as root, from a directory its unprivileged runs can read (not
under a private home directory):

```sh
sudo /usr/lib/fenders/fenders-node --state /var/lib/fenders/node --build /usr/lib/fenders \
  --cgroup-root /sys/fs/cgroup/fenders-runs \
  --control https://control.internal:9091 --control-pin "PIN OF control" \
  --ca pki/ca.pem --cert pki/node.pem --key pki/node.key \
  --host 0.0.0.0 --port 9443 --cpu-percent 200 --memory-mib 1024 --max-instances 4
```

`deploy/artifacts/worker/` has its systemd unit.

A node that runs tenants you do not trust with unlimited outbound transfer
must be registered with `egress_budget_required` and started with
`--egress-budget` ([status](STATUS.md#outbound-byte-limit)).

## 4. A tenant for each customer

As the operator:

```sh
# A tenant, with what it may use at once and its monthly transfer.
POST /v1/tenants
{"name": "acme", "allowance": {"cpu_percent": 200, "memory_mib": 1024,
  "storage_bytes": 1073741824, "instances": 2, "transfer_bytes": 1073741824}}
# -> {"id": "TENANT", …}; a default project is created with it.

GET  /v1/tenants/TENANT/projects            # -> [{"id": "PROJECT", …}]
POST /v1/tenants/TENANT/projects            {"name": "staging"}
PATCH /v1/tenants/TENANT                    {"allowance": {…}}

# A key for that tenant, optionally for one project.
POST /v1/tenants/TENANT/api-keys
{"name": "product", "permissions": ["read", "apps:write", "runs:write"],
 "ttl_seconds": 2592000}
# -> {"id": …, "token": "fnd_tok_…"}   the token is shown once
DELETE /v1/tenants/TENANT/api-keys/KEY      # it stops working at once
```

Permissions: `read`, `apps:write`, `runs:write`, `projects:write`,
`connections:write`, `secrets:write`. A key lives at most 30 days
(`ttl_seconds` 60 to 2592000); re-issue with the operator credential.

The allowance is enforced in the transaction that admits work: a tenant at
its limit is refused, and nothing it does can take from another tenant.

## 5. What a tenant key does

The workspace API, under `/v1/workspaces/TENANT/…`. Its contract is served
by the control plane at `/api/openapi.json`, with a readable page at `/api`.
In short:

```sh
S=/v1/workspaces/TENANT/projects/PROJECT

POST $S/artifacts            (Content-Type: application/wasm, the component)   -> {"id": "ARTIFACT"}
GET  $S/artifacts/ARTIFACT/inspection     # "state": "valid" once a node inspected it

POST $S/apps/deploy          {"name": "worker", "artifact_id": "ARTIFACT",
                              "triggers": {"http": false, "manual": true}}
GET  $S/apps/APP             # "state": "ready"

POST $S/apps/APP/runs        {}                 # deploying never runs anything; this does
GET  $S/apps/APP/runs/RUN    # "state": "succeeded" | "failed" | "cancelled", "exit_code"
GET  $S/apps/APP/logs        # its output, secrets masked
```

Schedules and the HTTP trigger are `triggers`; secrets, connections to
external TCP endpoints and HTTPS origins, releases, events and usage are in
the contract.

## 6. The boundaries you can rely on, and check

`scripts/verify_embedding_live.sh` asserts each of these on a real node:

- A tenant key lists only its own workspace.
- A tenant key asking for another tenant's apps, one of its apps, or to run
  one is answered `404`, as for something that does not exist.
- A tenant key calling an operator endpoint (`POST /v1/tenants`,
  `GET /v1/nodes`) is answered `403`.
- No credential is `401`; a revoked key is `401` at once.
- No console is served: only `/api` and the API itself.

Each run is a VM of its own with its own cgroup and uid on the node, and
reaches only the destinations its app was given.

## Bringing your own console

The control plane is also a library. A binary of yours can serve files
beside the API from the same listener:

```rust
static CONSOLE: [fenders_control_plane::api::Asset; 1] = [fenders_control_plane::api::Asset {
    path: "/console/",
    content_type: "text/html; charset=utf-8",
    body: include_bytes!("../console/index.html"),
}];

#[tokio::main]
async fn main() {
    if let Err(error) = fenders_control_plane::server::run(&CONSOLE).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
```

For people signing in to such a console, `--browser-auth FILE` configures an
OIDC provider; sessions then reach the same API with a cookie and a CSRF
token. Without the flag, sign-in is off and only bearer credentials work.

## Limits

[STATUS.md](STATUS.md) lists them all. The ones that shape an integration:
the operator credential is a single unscoped token; keys live 30 days at
most; the operator calls are not in the OpenAPI contract yet; HTTP apps'
traffic passes through one control-plane process.
