//! Opt-in actual WASI component execution. This native engine proves the probe
//! can distinguish a matching ceiling from an incorrectly configured limiter;
//! it is not KVM/runtime memory qualification.
use fenders_runtime_limits::AggregateLimits;
use wasmtime::{
    Config, Engine, Store,
    component::{Component, Linker, ResourceTable},
};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView, p2::pipe::MemoryOutputPipe};
struct Host {
    wasi: WasiCtx,
    table: ResourceTable,
    limits: AggregateLimits,
}

#[tokio::test]
async fn multiple_core_instances_in_one_component_share_the_linear_memory_budget() {
    let config = Config::new();
    let engine = Engine::new(&config).unwrap();
    let bytes = wat::parse_str(
        r#"(component
      (core module $m (memory 3) (func (export "size") (result i32) memory.size))
      (core instance $a (instantiate $m))
      (core instance $b (instantiate $m))
      (func (export "a") (result u32) (canon lift (core func $a "size")))
      (func (export "b") (result u32) (canon lift (core func $b "size")))
    )"#,
    )
    .unwrap();
    let component = Component::new(&engine, bytes).unwrap();
    let linker = Linker::new(&engine);
    for (pages, allowed) in [(4, false), (6, true)] {
        let mut store = Store::new(&engine, AggregateLimits::new(pages * 65536));
        store.limiter(|limits| limits);
        let result = linker.instantiate_async(&mut store, &component).await;
        assert_eq!(result.is_ok(), allowed);
        if let Ok(instance) = result {
            assert_eq!(store.data().charged_bytes(), 6 * 65536);
            let function = instance
                .get_typed_func::<(), (u32,)>(&mut store, "b")
                .unwrap();
            assert_eq!(function.call_async(&mut store, ()).await.unwrap(), (3,));
        }
    }
}
impl WasiView for Host {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}
async fn execute(bytes: &[u8], limit: usize, requested: usize) -> (bool, String) {
    let mut config = Config::new();
    config.consume_fuel(true);
    let engine = Engine::new(&config).unwrap();
    let component = Component::new(&engine, bytes).unwrap();
    let output = MemoryOutputPipe::new(8192);
    let host = Host {
        wasi: WasiCtxBuilder::new()
            .stdout(output.clone())
            .stderr(output.clone())
            .env("TEST_MODE", "memory-limit")
            .env("TEST_MEMORY_MIB", requested.to_string())
            .build(),
        table: ResourceTable::new(),
        limits: AggregateLimits::new(limit * 1024 * 1024),
    };
    let mut store = Store::new(&engine, host);
    store.limiter(|host| &mut host.limits);
    store.set_fuel(50_000_000).unwrap();
    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker).unwrap();
    let command =
        wasmtime_wasi::p2::bindings::Command::instantiate_async(&mut store, &component, &linker)
            .await
            .unwrap();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        command.wasi_cli_run().call_run(&mut store),
    )
    .await
    .unwrap();
    (
        matches!(result, Ok(Ok(()))),
        String::from_utf8(output.contents().to_vec()).unwrap(),
    )
}
#[tokio::test]
#[ignore = "requires FENDERS_MEMORY_COMPONENT built from examples/runtime-fixtures for wasm32-wasip2"]
async fn actual_memory_probe_verifies_the_ceiling_and_detects_both_directions_of_misconfiguration()
{
    let path = std::env::var_os("FENDERS_MEMORY_COMPONENT").expect(
        "build examples/runtime-fixtures fenders-command for wasm32-wasip2 and supply its path",
    );
    let bytes = std::fs::read(path).unwrap();
    for (limit, requested, expected) in [(4, 4, true), (8, 8, true), (2, 4, false), (8, 4, false)] {
        let (success, output) = execute(&bytes, limit, requested).await;
        println!("limit_mib={limit} requested_mib={requested} command_succeeded={success}");
        assert_eq!(
            success, expected,
            "limit={limit} requested={requested}: {output}"
        );
        let receipts = output
            .lines()
            .filter_map(|s| s.strip_prefix("FENDERS_MEMORY_LIMIT "))
            .collect::<Vec<_>>();
        if expected {
            assert_eq!(receipts.len(), 1);
            let receipt: serde_json::Value = serde_json::from_str(receipts[0]).unwrap();
            println!("{receipt}");
            assert_eq!(receipt["maximum_pages"], requested * 16);
            assert_eq!(receipt["beyond_limit_rejected"], true);
            let initial = receipt["initial_pages"].as_u64().unwrap();
            assert!(initial > 0 && initial < (requested * 16) as u64);
            assert_eq!(
                receipt["touched_pages"].as_u64().unwrap(),
                (requested * 16) as u64 - initial
            );
        } else {
            assert!(
                receipts.is_empty(),
                "failed probe must not publish a successful receipt"
            );
        }
    }
}
