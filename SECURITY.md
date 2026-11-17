# Security

Fenders exists to isolate code its operator does not trust, so a flaw in that
isolation matters more than most bugs. Please report one privately.

## Reporting

Use GitHub's private vulnerability reporting on this repository
(**Security → Report a vulnerability**). Do not open a public issue for
anything that lets a guest, a tenant or an unauthenticated caller do what it
should not.

Say what you ran, on what revision, and what you observed. A component or a
sequence of API calls that shows it is the most useful thing you can send.

## What counts

- A guest reading or changing anything outside its VM, or reaching a network
  destination its launch did not name.
- One tenant reading, changing, starving or billing another.
- A caller acting without a credential, beyond a credential's scope, or after
  it was revoked or its generation fenced.
- A run or a compile escaping its cgroup, uid, Landlock or seccomp
  confinement on the node.

## What is already known

[docs/STATUS.md](docs/STATUS.md) lists the limits accepted today, such as a
node being trusted to mask secrets in output, and a removed connection being
enforced by stopping the run through its node. A report that one of those
limits exists is not news; a report that one is worse than written is.

Fenders is pre-1.0 and has not been qualified for hostile public multi-tenant
operation. Only the latest revision of `main` is supported.
