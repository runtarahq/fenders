# Upstream provenance and guest adaptation

Source: crates.io `wasmtime-wasi-http` 50.0.0, corresponding to the pinned
Wasmtime v50.0.0 release, re-ported from the 38.0.3 adaptation. Its licence (Apache-2.0 WITH LLVM-exception) is in `LICENSE`. In 50.0.0 `wasi:http` 0.2 and 0.3 share one outgoing path
(`default_send_request`, called through `WasiHttpHooks::send_request`), so the
adaptation below applies to both versions.

The `fenders-platform` feature selects an origin-specific CA from
`FENDERS_HTTP_SERVICE_ROOTS` in the native embedding environment and disables TLS
resumption. The `fenders-service-trust` Rust crate supplies the same bounded parser
to the control plane, node and runtime. Entries use explicit canonical HTTPS
origins and DER-hex certificates. An entry replaces public trust for that origin
only; unlisted origins retain upstream public roots. Malformed policies fail
closed, including malformed entries for a different origin. Certificate chain,
name and time verification remain enabled. Trust never grants destination access.

The legacy `FENDERS_HTTP_CA_DER_HEX` global-CA setting remains for standalone
research launches only when the new variable is absent. Platform nodes always
set the new variable, even when empty. No application environment override is
accepted. The public `platform::service_root_store` function permits testing the
actual adapter and its rustls version without process-global environment changes.

The feature also consumes `FENDERS_HTTP_PUBLIC_TARGETS` (always present on new
platform launches, including an empty string). The shared `fenders-egress` parser
validates exact HTTPS origins and pinned public IPv4 addresses. Requests must
match `FENDERS_HTTP_ALLOW`; public names connect through their immutable numeric
bindings, with the original origin hostname retained for certificate verification.
Other allowed requests require a numeric IPv4 address. There is no platform DNS
fallback, and public bindings cannot replace Web PKI roots with private service
roots. Without this variable, standalone research launches retain name lookup.
A partial environment containing public targets but no service-root variable
fails trust selection instead of falling back to global research CA injection.

TCP, TLS and HTTP setup share one deadline capped at five seconds; first-byte
and between-byte waits are capped at ten seconds. Shorter application options
apply. This closes an upstream gap where TCP setup had a timeout but the TLS
handshake did not. Responses, including redirects, are returned directly; a
component's follow-up request is separately authorized. Total streaming byte
and duration limits are separate work, not provided by these wait caps.

HTTP protocol, WASI resource handling, streaming, trailers, futures
and Hyper/Tokio I/O remain upstream. Changes are limited to
Cargo.toml, src/lib.rs, src/default_send_request.rs and the added
src/platform.rs, which reports upstream's shared `Error`. The native
ABI platform outside this crate supplies the required execution services and
independently enforces expiring numeric TCP leases. Customer public-HTTPS
resolution, grant lifecycle and live guest/fabric qualification remain pending;
this adapter foundation alone must not enable the customer feature.
