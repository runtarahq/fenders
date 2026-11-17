//! Customer-selectable app sizes and the worker limits each one implies.
use crate::model::WORKER_OVERHEAD_MIB;
use serde_json::{Value, json};

pub fn sizes() -> Value {
    json!([
        {"id":"small","cpu_percent":25,"guest_memory_mib":32,"vm_memory_mib":64,"wasm_linear_memory_mib":4,"reservation_memory_mib":64+WORKER_OVERHEAD_MIB,"status":"experimental"},
        {"id":"medium","cpu_percent":50,"guest_memory_mib":96,"vm_memory_mib":128,"wasm_linear_memory_mib":40,"reservation_memory_mib":128+WORKER_OVERHEAD_MIB,"status":"experimental"},
        {"id":"large","cpu_percent":100,"guest_memory_mib":224,"vm_memory_mib":256,"wasm_linear_memory_mib":104,"reservation_memory_mib":256+WORKER_OVERHEAD_MIB,"status":"experimental"}
    ])
}
