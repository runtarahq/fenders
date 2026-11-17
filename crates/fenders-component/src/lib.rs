//! Validation and AOT compilation for the pinned kernel-free Fenders runtime.
//! No Store is created and no component initialization or guest code is run.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use wasmtime::component::{Component, Linker, Resource, ResourceTable, types::ComponentItem};
use wasmtime::{Config, Engine, OptLevel};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_wasi_http::{WasiHttpCtx, WasiHttpCtxView, WasiHttpView};
pub mod cache;
mod rejection;
pub use rejection::{Rejection, rejection_code, rejection_receipt};

pub const RUNTIME: &str = "wasmtime-50.0.0-fenders-v1";
/// The compiler's own ceiling; each node enforces its configured upload cap below it.
pub const MAX_COMPONENT_BYTES: usize = 128 * 1024 * 1024;
pub const MAX_INSPECTION_BYTES: usize = 65536;

struct Host {
    wasi: WasiCtx,
    http: WasiHttpCtx,
    table: ResourceTable,
}
impl WasiView for Host {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}
impl WasiHttpView for Host {
    fn http(&mut self) -> WasiHttpCtxView<'_> {
        WasiHttpCtxView {
            ctx: &mut self.http,
            table: &mut self.table,
            hooks: wasmtime_wasi_http::default_hooks(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Inspection {
    pub format_version: u32,
    pub runtime: String,
    pub digest: String,
    pub bytes: usize,
    pub http: bool,
    pub command: bool,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
}

fn config() -> Config {
    let mut config = Config::new();
    config
        .wasm_component_model_async(true)
        .signals_based_traps(false)
        .memory_reservation(0)
        .memory_guard_size(0)
        .memory_reservation_for_growth(0)
        .memory_init_cow(false)
        .consume_fuel(true);
    config
}

pub fn inspect(wasm: &[u8]) -> Result<Inspection> {
    inspect_cached(wasm, None)
}

fn inspect_cached(wasm: &[u8], cache: Option<&Arc<cache::Cache>>) -> Result<Inspection> {
    ensure!(
        (8..=MAX_COMPONENT_BYTES).contains(&wasm.len()) && wasm[..8] == *b"\0asm\x0d\0\x01\0",
        Rejection::InvalidComponent
    );
    // Broad validation rejects malformed input without classifying infrastructure
    // or native-code compiler failures as permanent customer errors. The pinned
    // Wasmtime engine below remains authoritative for runtime compatibility.
    wasmparser::Validator::new_with_features(wasmparser::WasmFeatures::all())
        .validate_all(wasm)
        .map_err(|_| Rejection::InvalidComponent)?;
    // This compile only types the component against the host interfaces; its
    // code is discarded, so it skips optimization (`compile` produces the code
    // that runs, for the runtime's own target).
    let mut config = config();
    config.cranelift_opt_level(OptLevel::None);
    cached(&mut config, cache)?;
    let engine = Engine::new(&config)?;
    let component = Component::new(&engine, wasm)
        .map_err(anyhow::Error::from)
        .context("component validation failed")?;
    let mut linker = Linker::<Host>::new(&engine);
    // Match the runtime's host interface set, not a string-based WASI allowlist.
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)?;
    wasmtime_wasi::p3::add_to_linker(&mut linker)?;
    wasmtime_wasi_http::p3::add_to_linker(&mut linker)?;
    let pre = linker
        .instantiate_pre(&component)
        .map_err(|_| Rejection::UnsupportedImports)
        .context("component imports are incompatible with the Fenders runtime")?;
    // The generated *Pre constructors check export names, but
    // interface function types are checked only when loading an instance.
    // Do the same typed checks here without executing component initialization.
    let export = |interface, function| {
        let (_, index) = component.get_export(None, interface)?;
        match component.get_export(Some(&index), function)?.0 {
            ComponentItem::ComponentFunc(func) => Some(func),
            _ => None,
        }
    };
    // A WASI 0.2 command, or a 0.3 one whose `run` is lifted async.
    let command = ["wasi:cli/run@0.2.6", "wasi:cli/run@0.3.0"]
        .into_iter()
        .any(|interface| {
            export(interface, "run").is_some_and(|f| {
                f.typecheck::<(), (Result<(), ()>,)>(&pre.instance_type())
                    .is_ok()
            })
        });
    use wasmtime_wasi_http::p2::bindings::http::types::{IncomingRequest, ResponseOutparam};
    let http_02 = export("wasi:http/incoming-handler@0.2.6", "handle").is_some_and(|f| {
        f.typecheck::<(Resource<IncomingRequest>, Resource<ResponseOutparam>), ()>(
            &pre.instance_type(),
        )
        .is_ok()
    });
    // A WASI 0.3 service: `handle` is an async function from request to response.
    use wasmtime_wasi_http::p3::bindings::http::types::ErrorCode;
    use wasmtime_wasi_http::p3::{Request, Response};
    let http_03 = export("wasi:http/handler@0.3.0", "handle").is_some_and(|f| {
        f.async_()
            && f.typecheck::<(Resource<Request>,), (Result<Resource<Response>, ErrorCode>,)>(
                &pre.instance_type(),
            )
            .is_ok()
    });
    let http = http_02 || http_03;
    ensure!(command || http, Rejection::IncompatibleEntryPoints);
    let ty = component.component_type();
    let mut imports: Vec<_> = ty
        .imports(&engine)
        .map(|(name, _)| name.to_owned())
        .collect();
    let mut exports: Vec<_> = ty
        .exports(&engine)
        .map(|(name, _)| name.to_owned())
        .collect();
    imports.sort();
    exports.sort();
    ensure!(
        imports.len() <= 128
            && exports.len() <= 128
            && imports
                .iter()
                .chain(&exports)
                .all(|n| !n.is_empty() && n.len() <= 256 && !n.chars().any(char::is_control)),
        Rejection::InterfaceLimits
    );
    let inspection = Inspection {
        format_version: 1,
        runtime: RUNTIME.into(),
        digest: format!("{:x}", Sha256::digest(wasm)),
        bytes: wasm.len(),
        http,
        command,
        imports,
        exports,
    };
    ensure!(
        serde_json::to_vec(&inspection)?.len() <= MAX_INSPECTION_BYTES,
        Rejection::InterfaceLimits
    );
    Ok(inspection)
}

/// Must run under the compiler worker's CPU, memory, filesystem and syscall limits.
/// The output is trusted native code only for this pinned runtime and target.
pub fn compile(wasm: &[u8]) -> Result<(Vec<u8>, Inspection)> {
    compile_cached(wasm, None)
}

/// The caches of a compile's two passes, which share one store.
pub struct Caches {
    pub inspection: Arc<cache::Cache>,
    pub code: Arc<cache::Cache>,
}

/// [`compile`], looking each function up in `caches` first. The code is the
/// same with or without them.
pub fn compile_cached(wasm: &[u8], caches: Option<&Caches>) -> Result<(Vec<u8>, Inspection)> {
    let metadata = inspect_cached(wasm, caches.map(|c| &c.inspection))?;
    let mut config = config();
    config.target("x86_64-unknown-linux-musl")?;
    cached(&mut config, caches.map(|c| &c.code))?;
    let engine = Engine::new(&config)?;
    Ok((engine.precompile_component(wasm)?, metadata))
}

fn cached(config: &mut Config, cache: Option<&Arc<cache::Cache>>) -> Result<()> {
    if let Some(cache) = cache {
        config.enable_incremental_compilation(cache.clone())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const COMMAND: &str = r#"(component
      (core module $m (func (export "run") (result i32) i32.const 0))
      (core instance $i (instantiate $m))
      (func $run (result (result)) (canon lift (core func $i "run")))
      (instance $cli (export "run" (func $run)))
      (export "wasi:cli/run@0.2.0" (instance $cli)))"#;
    const HTTP: &str = r#"
      (import "wasi:http/types@0.2.6" (instance $http-types
        (export "incoming-request" (type (sub resource)))
        (export "response-outparam" (type (sub resource)))))
      (alias export $http-types "incoming-request" (type $request))
      (alias export $http-types "response-outparam" (type $response))
      (core module $handler (func (export "handle") (param i32 i32)))
      (core instance $handler-instance (instantiate $handler))
      (func $handle (param "request" (own $request)) (param "response" (own $response))
        (canon lift (core func $handler-instance "handle")))
      (instance $http (export "handle" (func $handle)))
      (export "wasi:http/incoming-handler@0.2.6" (instance $http))
    "#;
    #[test]
    fn http_and_dual_signatures_require_correct_resource_types() {
        let http = wat::parse_str(format!("(component {HTTP})")).unwrap();
        let info = inspect(&http).unwrap();
        assert!(info.http);
        assert!(!info.command);
        let dual = wat::parse_str(COMMAND.replacen("(component", &format!("(component {HTTP}"), 1))
            .unwrap();
        let info = inspect(&dual).unwrap();
        assert!(info.http && info.command);
        let swapped = wat::parse_str(format!(
            "(component {})",
            HTTP.replace("(own $request)", "(own $response)").replace(
                "(own $response))\n        (canon",
                "(own $request))\n        (canon"
            )
        ))
        .unwrap();
        assert!(inspect(&swapped).is_err());
    }
    #[test]
    fn typed_command_and_digest() {
        let wasm = wat::parse_str(COMMAND).unwrap();
        let info = inspect(&wasm).unwrap();
        assert!(info.command);
        assert!(!info.http);
        assert_eq!(info.exports, vec!["wasi:cli/run@0.2.0"]);
        assert_eq!(info.digest, format!("{:x}", Sha256::digest(&wasm)));
        assert_eq!(info.runtime, RUNTIME);
        assert_eq!(inspect(&wasm).unwrap(), info);
    }
    #[test]
    fn rejects_invalid_empty_core_and_name_spoofing() {
        for bytes in [
            b"\0asm\x0d\0\x01\0".to_vec(),
            b"\0asm\x01\0\0\0".to_vec(),
            b"\0asm\x0d\0\x01\0invalid".to_vec(),
            wat::parse_str(COMMAND.replace("(result (result))", "(result u32)")).unwrap(),
        ] {
            assert!(inspect(&bytes).is_err());
        }
    }
    #[test]
    fn rejects_unsupported_host_imports() {
        let wasm = wat::parse_str(COMMAND.replacen(
            "(component",
            "(component (import \"untrusted:host/magic\" (instance (export \"call\" (func))))",
            1,
        ))
        .unwrap();
        assert!(format!("{:#}", inspect(&wasm).unwrap_err()).contains("imports are incompatible"));
    }
    /// `run` returning `value`, beside a library module both share.
    fn with_library(value: i32) -> Vec<u8> {
        let library = (0..16)
            .map(|i| {
                format!(
                    "(func (export \"f{i}\") (param i32) (result i32)
                       (local i32) (loop $l (local.set 1 (i32.add (local.get 1) (i32.mul (local.get 0) (i32.const {i}))))
                       (br_if $l (i32.lt_u (local.get 1) (i32.const 1000)))) (local.get 1))"
                )
            })
            .collect::<String>();
        wat::parse_str(COMMAND.replacen(
            "(core module $m (func (export \"run\") (result i32) i32.const 0))",
            &format!(
                "(core module $lib {library}) (core instance (instantiate $lib))
                 (core module $m (func (export \"run\") (result i32) i32.const {value}))"
            ),
            1,
        ))
        .unwrap()
    }
    /// What the node does with a compile's records: stores each entry.
    fn store_records(store: &std::path::Path, records: &std::path::Path) {
        use std::io::Read;
        let data = std::fs::read(records).unwrap();
        let mut data = data.as_slice();
        let mut take = |n: usize| {
            let mut buf = vec![0; n];
            data.read_exact(&mut buf).unwrap();
            buf
        };
        let len = |take: &mut dyn FnMut(usize) -> Vec<u8>| {
            u32::from_le_bytes(take(4).try_into().unwrap()) as usize
        };
        let mut taken = 0;
        let total = std::fs::metadata(records).unwrap().len() as usize;
        while taken < total {
            let key = len(&mut take);
            let key = take(key);
            let value = len(&mut take);
            let path = cache::entry_path(store, &key).unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, take(value)).unwrap();
            taken += 8 + key.len() + value;
        }
    }
    fn caches(dir: &std::path::Path, store: &std::path::Path) -> Caches {
        let records = |name: &str| {
            let file = std::fs::File::create(dir.join(name)).unwrap();
            Arc::new(cache::Cache::new(store.to_path_buf(), file))
        };
        Caches {
            inspection: records("inspection"),
            code: records("code"),
        }
    }
    // `compile` targets x86-64, which a build for another host cannot.
    #[test]
    #[cfg_attr(not(target_arch = "x86_64"), ignore)]
    fn a_component_reuses_the_functions_it_shares_with_one_compiled_before() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        let (first, second) = (with_library(0), with_library(1));
        let caches_first = caches(dir.path(), &store);
        let (code, _) = compile_cached(&first, Some(&caches_first)).unwrap();
        caches_first.inspection.finish();
        caches_first.code.finish();
        assert_eq!(caches_first.code.counts().0, 0, "the store starts empty");
        assert_eq!(code, compile(&first).unwrap().0);
        for pass in ["inspection", "code"] {
            store_records(&store, &dir.path().join(pass));
        }
        let caches_second = caches(dir.path(), &store);
        let (code, info) = compile_cached(&second, Some(&caches_second)).unwrap();
        let (hits, misses) = caches_second.code.counts();
        assert!(
            hits >= 16,
            "the library's functions are found: {hits} hits, {misses} misses"
        );
        assert!(caches_second.inspection.counts().0 >= 16);
        assert_eq!(
            (code, info),
            compile(&second).unwrap(),
            "the code is the same cached or not"
        );
    }
    // `compile` targets x86-64, which a build for another host cannot.
    #[test]
    #[cfg_attr(not(target_arch = "x86_64"), ignore)]
    fn a_store_entry_is_used_only_under_its_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        let wasm = with_library(0);
        let caches_first = caches(dir.path(), &store);
        compile_cached(&wasm, Some(&caches_first)).unwrap();
        caches_first.code.finish();
        caches_first.inspection.finish();
        // An entry stored under the wrong key is never found.
        let other = dir.path().join("other");
        let data = std::fs::read(dir.path().join("code")).unwrap();
        let key = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
        let mut wrong = data[4..4 + key].to_vec();
        wrong[0] ^= 1;
        let value = &data[8 + key
            ..8 + key + u32::from_le_bytes(data[4 + key..8 + key].try_into().unwrap()) as usize];
        let path = cache::entry_path(&other, &wrong).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, value).unwrap();
        let caches_other = caches(dir.path(), &other);
        let (code, _) = compile_cached(&wasm, Some(&caches_other)).unwrap();
        assert_eq!(caches_other.code.counts().0, 0);
        assert_eq!(code, compile(&wasm).unwrap().0);
    }
    #[test]
    fn inspection_never_initializes_guest() {
        let wasm = wat::parse_str(COMMAND.replace(
            "(core module $m",
            "(core module $m (func $start unreachable) (start $start)",
        ))
        .unwrap();
        assert!(inspect(&wasm).unwrap().command);
    }
}

#[cfg(test)]
mod demo_tests;
