//! Aggregate linear-memory admission for one Wasmtime Store. The runtime uses
//! one Store per command/request and drops it before admitting the next request.
//! Shared memories must remain disabled: Wasmtime does not call this limiter
//! for shared memory. This crate deliberately does not enable Wasmtime threads.
use wasmtime::{Error, ResourceLimiter, Result, StoreLimits, StoreLimitsBuilder};

pub struct AggregateLimits {
    limit: usize,
    charged: usize,
    pending: usize,
    structural: StoreLimits,
}
impl AggregateLimits {
    pub fn new(memory_bytes: usize) -> Self {
        Self::with_structure(memory_bytes, 32, 10_000, 16, 32)
    }
    /// The same admission with a launch's own instance, table-element, table
    /// and memory limits.
    pub fn with_structure(
        memory_bytes: usize,
        instances: usize,
        table_elements: usize,
        tables: usize,
        memories: usize,
    ) -> Self {
        Self {
            limit: memory_bytes,
            charged: 0,
            pending: 0,
            structural: StoreLimitsBuilder::new()
                .instances(instances)
                .memories(memories)
                .tables(tables)
                .table_elements(table_elements)
                .build(),
        }
    }
    /// Successful admitted bytes, conservatively including allocations from a
    /// failed instantiation without a matching failure callback. No guest-driven
    /// reset: the budget is released only when the Store itself is dropped.
    pub fn charged_bytes(&self) -> usize {
        self.charged
    }
}
impl ResourceLimiter for AggregateLimits {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool> {
        // Calls are synchronous and exclusive. A subsequent growth means the
        // previous one did not invoke memory_grow_failed; commit that admission.
        self.pending = 0;
        if current > self.charged || !self.structural.memory_growing(current, desired, maximum)? {
            return Ok(false);
        }
        let Some(delta) = desired.checked_sub(current) else {
            return Ok(false);
        };
        let Some(total) = self.charged.checked_add(delta).filter(|n| *n <= self.limit) else {
            return Ok(false);
        };
        self.charged = total;
        self.pending = delta;
        Ok(true)
    }
    fn memory_grow_failed(&mut self, error: Error) -> Result<()> {
        // Refund only this operation's tentative bytes, never prior memories.
        self.charged -= self.pending;
        self.pending = 0;
        self.structural.memory_grow_failed(error)
    }
    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool> {
        self.structural.table_growing(current, desired, maximum)
    }
    fn table_grow_failed(&mut self, error: Error) -> Result<()> {
        self.structural.table_grow_failed(error)
    }
    fn instances(&self) -> usize {
        self.structural.instances()
    }
    fn tables(&self) -> usize {
        self.structural.tables()
    }
    fn memories(&self) -> usize {
        self.structural.memories()
    }
}

#[cfg(test)]
mod tests;
