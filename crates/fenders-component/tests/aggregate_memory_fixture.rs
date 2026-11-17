//! Native validation of the exact two-memory command used by the KVM harness.
//! Passing this test validates the probe, not the kernel-free runtime itself.
#[path = "../../../examples/runtime-fixtures/aggregate_memory.rs"]
mod fixture;

use fenders_runtime_limits::AggregateLimits;
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder, Trap};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

struct Host {
    wasi: WasiCtx,
    table: ResourceTable,
    aggregate: AggregateLimits,
    per_memory: StoreLimits,
}
impl WasiView for Host {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

async fn run(engine: &Engine, component: &Component, mib: usize, aggregate: bool) -> (bool, usize) {
    let mut store = Store::new(
        engine,
        Host {
            wasi: WasiCtxBuilder::new().build(),
            table: ResourceTable::new(),
            aggregate: AggregateLimits::new(mib * 1024 * 1024),
            per_memory: StoreLimitsBuilder::new()
                .memory_size(mib * 1024 * 1024)
                .build(),
        },
    );
    if aggregate {
        store.limiter(|host| &mut host.aggregate);
    } else {
        store.limiter(|host| &mut host.per_memory);
    }
    store.set_fuel(200_000_000).unwrap();
    let mut linker = Linker::new(engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker).unwrap();
    let command =
        wasmtime_wasi::p2::bindings::Command::instantiate_async(&mut store, component, &linker)
            .await
            .unwrap();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        command.wasi_cli_run().call_run(&mut store),
    )
    .await
    .unwrap();
    let passed = match result {
        Ok(Ok(())) => true,
        Err(error) => {
            // A failed assertion must be the reason, not unsupported imports,
            // an instantiation failure, fuel exhaustion or an unrelated error.
            assert_eq!(
                error.downcast_ref::<Trap>(),
                Some(&Trap::UnreachableCodeReached),
                "{error:#}"
            );
            false
        }
        Ok(Err(())) => panic!("probe returned an unexpected WASI command error"),
    };
    (passed, store.data().aggregate.charged_bytes())
}

#[tokio::test]
async fn actual_two_memory_command_detects_incorrect_limits_and_the_old_per_memory_policy() {
    let mut config = Config::new();
    config
        .signals_based_traps(false)
        .memory_reservation(0)
        .memory_guard_size(0)
        .memory_reservation_for_growth(0)
        .memory_init_cow(false)
        .consume_fuel(true);
    let engine = Engine::new(&config).unwrap();
    for expected_mib in [4, 8] {
        let wasm = fixture::component(expected_mib).unwrap();
        let inspection = fenders_component::inspect(&wasm).unwrap();
        assert!(inspection.command && !inspection.http);
        assert!(inspection.imports.is_empty());
        let component = Component::new(&engine, wasm).unwrap();
        for (mib, aggregate, expected_pass) in [
            (expected_mib, true, true),
            (expected_mib / 2, true, false),
            (expected_mib * 2, true, false),
            (expected_mib, false, false),
        ] {
            let (passed, charged) = run(&engine, &component, mib as usize, aggregate).await;
            println!(
                "expected_mib={expected_mib} configured_mib={mib} aggregate={aggregate} command_succeeded={passed} charged_bytes={charged} component_sha256={}",
                inspection.digest
            );
            assert_eq!(passed, expected_pass);
            if aggregate {
                assert!(charged <= mib as usize * 1024 * 1024);
                if passed {
                    assert_eq!(charged, expected_mib as usize * 1024 * 1024);
                }
            }
        }
    }
}

#[test]
fn unsupported_probe_sizes_are_rejected_before_generation() {
    for size in [0, 1, 2, 3, 505, 1024, u64::MAX] {
        assert!(fixture::component(size).is_err());
    }
}
