//! Node ↔ control-plane protocol: report and assignment validation, generation
//! and boot identities, shared limits, and the pinned mutual-TLS transport.
pub mod app_https;
pub mod app_runtime;
pub mod application_headers;
pub mod artifacts;
pub mod egress_budget;
pub mod egress_periods;
pub mod egress_usage;
pub mod error;
pub mod execution_identity;
pub mod model;
pub mod pki;
pub mod schedule;
pub mod transport;
pub mod value;
pub mod workloads;
