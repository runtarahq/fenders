//! How a guest's outgoing HTTP request is sent on the Fenders platform.
//!
//! The guest runtime uses the stock `wasmtime-wasi-http`; its
//! `WasiHttpHooks::send_request` checks the request against the launch's
//! allowed origins and then calls [`send_request`]. That is upstream's
//! `default_send_request`, with the connection made the platform's way:
//!
//! - **Destinations:** only pinned addresses from the launch's bindings, with
//!   no DNS lookup ([`platform::request_target`]).
//! - **Trust:** an origin's own CA when the launch names one, public roots
//!   otherwise, and no TLS resumption ([`platform::root_store`]).
//! - **Timeouts:** TCP, TLS and HTTP setup share one deadline of at most 5 s,
//!   which upstream lacks for the TLS handshake. Waits for response bytes are
//!   capped at 10 s.
//!
//! Everything else, the HTTP protocol, WASI resources and streaming, is
//! upstream's. `src/send.rs` is derived from `wasmtime-wasi-http` 50.0.3
//! (Apache-2.0 WITH LLVM-exception, `LICENSE-wasmtime`).
pub mod platform;
mod send;

pub use send::send_request;
