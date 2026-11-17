# Contributing

## Rules that every change keeps

- The backend is Rust; the KVM launcher is C. No other runtime, subprocess
  adapter or fallback.
- WASM execution stays kernel-free. Deploying or starting an app never
  implicitly invokes a command.
- Tenant isolation, transactional quotas, generation fencing, idempotency and
  host confinement are preserved by every change. A protection is not claimed
  from compilation or unit tests alone, and never waived to get a passing
  demonstration.
- A capability is **opt-in per launch spec**. A spec that does not ask for it
  takes exactly the path it took before: no new thread, pipe or system call.
  `scripts/compare_shim_default_path.sh` compares the system calls of two
  builds to show it.
- The node stays a thin launcher with its runs in memory. Durable state about
  a run belongs to its control plane.
- Calls added to the run channel are optional capabilities an endpoint may
  refuse, not a protocol bump: other control planes speak it too.
- Connections are generic host/port TCP permissions and HTTPS origins to
  externally operated services. Fenders does not provision services.

## Working on it

```sh
make check                        # rustfmt and clippy, warnings are errors
export FENDERS_TEST_DATABASE_URL='postgresql://USER:PASSWORD@HOST/TEST_DATABASE'
make test                         # a disposable PostgreSQL 17 database
make build-node                   # Linux x86-64 with KVM
bash scripts/verify_network_native.sh
```

A change to the node, the shim, the launcher or the guest runtime is shown on
a real KVM node, not only in tests: the `scripts/verify_*_live.sh` scripts
each run one area end to end on a single machine and print a result.

Update [docs/STATUS.md](docs/STATUS.md) in the same change that alters what
works or a limit. State limits plainly.

## Licence

Contributions are accepted under the Apache License, Version 2.0, the licence
of this repository.
