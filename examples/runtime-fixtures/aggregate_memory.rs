//! Shared source for native-engine validation and the live KVM harness. This
//! fixture needs no guest OS or host imports; only the WASI command export.
pub fn component(linear_mib: u64) -> Result<Vec<u8>, String> {
    if !(4..=504).contains(&linear_mib) {
        return Err("aggregate probe supports 4 to 504 MiB catalog ceilings".into());
    }
    let source = include_str!("aggregate-memory.wat")
        .replace("__PAGES_PER_MEMORY__", &(linear_mib * 8).to_string());
    wat::parse_str(source).map_err(|e| e.to_string())
}
