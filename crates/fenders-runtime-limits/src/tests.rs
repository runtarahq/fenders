use super::*;
use wasmtime::{Engine, Instance, Memory, MemoryType, Module, Store};
const PAGE: usize = 65536;
fn store(engine: &Engine, pages: usize) -> Store<AggregateLimits> {
    let mut store = Store::new(engine, AggregateLimits::new(pages * PAGE));
    store.limiter(|limits| limits);
    store
}
#[test]
fn multiple_memories_share_the_budget_and_denial_does_not_consume_it() {
    let engine = Engine::default();
    let mut store = store(&engine, 4);
    let a = Memory::new(&mut store, MemoryType::new(1, None)).unwrap();
    let b = Memory::new(&mut store, MemoryType::new(1, None)).unwrap();
    assert_eq!(store.data().charged_bytes(), 2 * PAGE);
    assert!(a.grow(&mut store, 3).is_err());
    assert_eq!(store.data().charged_bytes(), 2 * PAGE);
    assert_eq!(a.grow(&mut store, 2).unwrap(), 1);
    assert!(b.grow(&mut store, 1).is_err());
    assert!(Memory::new(&mut store, MemoryType::new(1, None)).is_err());
    assert_eq!(store.data().charged_bytes(), 4 * PAGE);
}
#[test]
fn imports_are_not_double_charged_and_fresh_stores_have_independent_budgets() {
    let engine = Engine::default();
    let module = Module::new(
        &engine,
        wat::parse_str("(module (import \"host\" \"memory\" (memory 1)))").unwrap(),
    )
    .unwrap();
    let mut first = store(&engine, 2);
    let memory = Memory::new(&mut first, MemoryType::new(1, None)).unwrap();
    for _ in 0..3 {
        Instance::new(&mut first, &module, &[memory.into()]).unwrap();
    }
    assert_eq!(first.data().charged_bytes(), PAGE);
    memory.grow(&mut first, 1).unwrap();
    let mut second = store(&engine, 2);
    Memory::new(&mut second, MemoryType::new(2, None)).unwrap();
    assert_eq!(second.data().charged_bytes(), 2 * PAGE);
}
#[test]
fn combined_initial_memories_cannot_bypass_a_component_budget() {
    let engine = Engine::default();
    let module = Module::new(
        &engine,
        wat::parse_str("(module (memory 3) (memory 3))").unwrap(),
    )
    .unwrap();
    let mut state = store(&engine, 4);
    assert!(Instance::new(&mut state, &module, &[]).is_err());
    assert!(state.data().charged_bytes() <= 4 * PAGE);
    let mut enough = store(&engine, 6);
    Instance::new(&mut enough, &module, &[]).unwrap();
    assert_eq!(enough.data().charged_bytes(), 6 * PAGE);
}
#[test]
fn declared_maximum_and_zero_size_memory_inventory_remain_bounded() {
    let engine = Engine::default();
    let mut state = store(&engine, 4);
    let memory = Memory::new(&mut state, MemoryType::new(1, Some(1))).unwrap();
    assert!(memory.grow(&mut state, 1).is_err());
    assert_eq!(state.data().charged_bytes(), PAGE);
    Memory::new(&mut state, MemoryType::new(3, None)).unwrap();
    let mut zero = store(&engine, 0);
    // Wasmtime's structural counts apply to module instantiation, the path a
    // guest component uses, rather than embedder-created Memory handles.
    let full = Module::new(
        &engine,
        wat::parse_str(format!("(module {})", "(memory 0)".repeat(32))).unwrap(),
    )
    .unwrap();
    let extra = Module::new(&engine, wat::parse_str("(module (memory 0))").unwrap()).unwrap();
    Instance::new(&mut zero, &full, &[]).unwrap();
    assert!(Instance::new(&mut zero, &extra, &[]).is_err());
    assert_eq!(zero.data().charged_bytes(), 0);
}
#[test]
fn shared_memories_cannot_bypass_limiter_in_the_supported_engine_build() {
    assert!(
        Module::new(
            &Engine::default(),
            wat::parse_str("(module (memory 1 2 shared))").unwrap()
        )
        .is_err()
    );
}
#[test]
fn failed_growth_refunds_only_the_pending_delta_and_overflows_are_denied() {
    let mut limits = AggregateLimits::new(4 * PAGE);
    assert!(limits.memory_growing(0, PAGE, None).unwrap());
    assert!(limits.memory_growing(0, 2 * PAGE, None).unwrap());
    limits
        .memory_grow_failed(Error::msg("injected allocation failure"))
        .unwrap();
    assert_eq!(limits.charged_bytes(), PAGE);
    limits
        .memory_grow_failed(Error::msg("duplicate failure"))
        .unwrap();
    assert_eq!(limits.charged_bytes(), PAGE);
    assert!(!limits.memory_growing(PAGE, 0, None).unwrap());
    assert!(!limits.memory_growing(0, usize::MAX, None).unwrap());
    assert_eq!(limits.charged_bytes(), PAGE);
    assert!(limits.memory_growing(PAGE, 4 * PAGE, None).unwrap());
    assert_eq!(limits.charged_bytes(), 4 * PAGE);
}

#[test]
fn real_engine_allocation_failure_releases_only_its_growth_reservation() {
    use std::sync::Arc;
    use wasmtime::{Config, LinearMemory, MemoryCreator};
    struct FixedMemory(Box<[u8]>);
    // Owned zeroed storage remains stable for its lifetime. This fixture never
    // grows, executes guest code or enables unchecked/signal-based accesses.
    unsafe impl LinearMemory for FixedMemory {
        fn byte_size(&self) -> usize {
            self.0.len()
        }
        fn byte_capacity(&self) -> usize {
            self.0.len()
        }
        fn grow_to(&mut self, size: usize) -> Result<()> {
            if size <= self.0.len() {
                Ok(())
            } else {
                Err(Error::msg("injected backing allocation failure"))
            }
        }
        fn as_ptr(&self) -> *mut u8 {
            self.0.as_ptr().cast_mut()
        }
    }
    struct FixedCreator;
    // All buffers are private to the engine. Refuse any requested guard or
    // reservation the heap-backed test implementation cannot provide.
    unsafe impl MemoryCreator for FixedCreator {
        fn new_memory(
            &self,
            _ty: MemoryType,
            minimum: usize,
            _maximum: Option<usize>,
            reserved: Option<usize>,
            guard: usize,
        ) -> std::result::Result<Box<dyn LinearMemory>, String> {
            if guard != 0 || reserved.is_some_and(|n| n > minimum) {
                return Err("unsupported test memory reservation".into());
            }
            Ok(Box::new(FixedMemory(vec![0; minimum].into_boxed_slice())))
        }
    }
    let mut config = Config::new();
    config
        .signals_based_traps(false)
        .memory_reservation(0)
        .memory_reservation_for_growth(0)
        .memory_guard_size(0)
        .memory_init_cow(false)
        .with_host_memory(Arc::new(FixedCreator));
    let engine = Engine::new(&config).unwrap();
    let mut state = store(&engine, 4);
    let module = Module::new(
        &engine,
        wat::parse_str("(module (memory (export \"a\") 1) (memory (export \"b\") 1))").unwrap(),
    )
    .unwrap();
    let instance = Instance::new(&mut state, &module, &[]).unwrap();
    let first = instance.get_memory(&mut state, "a").unwrap();
    let second = instance.get_memory(&mut state, "b").unwrap();
    assert!(first.grow(&mut state, 2).is_err());
    assert_eq!(first.size(&state), 1);
    assert_eq!(state.data().charged_bytes(), 2 * PAGE);
    assert!(second.grow(&mut state, 1).is_err());
    assert_eq!(state.data().charged_bytes(), 2 * PAGE);
    Memory::new(&mut state, MemoryType::new(2, None)).unwrap();
    assert_eq!(state.data().charged_bytes(), 4 * PAGE);
}
#[test]
fn a_launch_sets_its_own_table_and_memory_counts() {
    let engine = Engine::default();
    let module = Module::new(
        &engine,
        wat::parse_str("(module (table 1 funcref) (table 1 funcref) (table 1 funcref))").unwrap(),
    )
    .unwrap();
    let mut few = Store::new(
        &engine,
        AggregateLimits::with_structure(PAGE, 32, 10_000, 2, 32),
    );
    few.limiter(|limits| limits);
    assert!(Instance::new(&mut few, &module, &[]).is_err());
    let mut enough = Store::new(
        &engine,
        AggregateLimits::with_structure(PAGE, 32, 10_000, 3, 32),
    );
    enough.limiter(|limits| limits);
    Instance::new(&mut enough, &module, &[]).unwrap();
}
/// SYN-788: a memory grown in 8 MiB steps from 17 pages to a 248 MiB limit,
/// as the stepped KVM probe does, is admitted at every step: the aggregate
/// limiter charges each step's delta, never an old and a new copy.
#[test]
fn stepped_growth_to_the_limit_is_admitted_at_every_step() {
    let mut config = wasmtime::Config::new();
    config
        .signals_based_traps(false)
        .memory_reservation(0)
        .memory_reservation_for_growth(0)
        .memory_guard_size(0)
        .memory_init_cow(false);
    let engine = Engine::new(&config).unwrap();
    let limit_pages = 248 * 16;
    let mut state = store(&engine, limit_pages);
    let memory = Memory::new(&mut state, MemoryType::new(17, None)).unwrap();
    let mut size = 17;
    while size < limit_pages {
        let step = (8 * 16).min(limit_pages - size);
        assert_eq!(
            memory.grow(&mut state, step as u64).unwrap(),
            size as u64,
            "at {size} pages"
        );
        size += step;
    }
    assert!(
        memory.grow(&mut state, 1).is_err(),
        "one page past the limit"
    );
    assert_eq!(state.data().charged_bytes(), limit_pages * PAGE);
}
