//! Stable customer-facing categories. Raw compiler messages never enter receipts.
use serde::Serialize;
use sha2::{Digest, Sha256};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    InvalidComponent,
    UnsupportedImports,
    IncompatibleEntryPoints,
    InterfaceLimits,
}
impl Rejection {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidComponent => "invalid-component",
            Self::UnsupportedImports => "unsupported-imports",
            Self::IncompatibleEntryPoints => "incompatible-entry-points",
            Self::InterfaceLimits => "interface-limits",
        }
    }
}
impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for Rejection {}
#[derive(Serialize)]
pub struct RejectionReceipt {
    format_version: u32,
    runtime: &'static str,
    digest: String,
    bytes: usize,
    error: &'static str,
}
pub fn rejection_code(error: &anyhow::Error) -> Option<&'static str> {
    error
        .downcast_ref::<Rejection>()
        .map(|reason| reason.code())
}
pub fn rejection_receipt(wasm: &[u8], error: &anyhow::Error) -> Option<RejectionReceipt> {
    Some(RejectionReceipt {
        format_version: 1,
        runtime: crate::RUNTIME,
        digest: format!("{:x}", Sha256::digest(wasm)),
        bytes: wasm.len(),
        error: rejection_code(error)?,
    })
}
