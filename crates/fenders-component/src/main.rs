use anyhow::{Result, ensure};
use fenders_component::{Caches, cache::Cache};
use std::{fs, io::Read, process::ExitCode, sync::Arc};
/// The node's compile cache for this compile, when it gives one: the scope's
/// store, read-only, and a record file for each pass. Without it, or when a
/// record file will not open, the compile runs uncached.
fn caches() -> Option<Caches> {
    let var = |name| std::env::var_os(name).filter(|v| !v.is_empty());
    let store = std::path::PathBuf::from(var("FENDERS_COMPILE_CACHE")?);
    let records = |name| {
        let file = fs::OpenOptions::new().write(true).open(var(name)?).ok()?;
        Some(Arc::new(Cache::new(store.clone(), file)))
    };
    Some(Caches {
        inspection: records("FENDERS_COMPILE_CACHE_INSPECTION")?,
        code: records("FENDERS_COMPILE_CACHE_CODE")?,
    })
}
fn run() -> Result<ExitCode> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 4 || (args.len() == 3 && args[1] != "inspect"),
        "usage: fenders-component INPUT OUTPUT [METADATA] | fenders-component inspect INPUT METADATA"
    );
    let inspect_only = args[1] == "inspect";
    let input = if inspect_only { &args[2] } else { &args[1] };
    let mut wasm = Vec::new();
    fs::File::open(input)?
        .take((fenders_component::MAX_COMPONENT_BYTES + 1) as u64)
        .read_to_end(&mut wasm)?;
    let result = if inspect_only {
        fenders_component::inspect(&wasm).map(|info| (None, info))
    } else {
        let caches = caches();
        let compiled = fenders_component::compile_cached(&wasm, caches.as_ref());
        if let Some(caches) = &caches {
            caches.inspection.finish();
            caches.code.finish();
        }
        compiled.map(|(compiled, info)| (Some(compiled), info))
    };
    match result {
        Ok((compiled, info)) => {
            if let Some(compiled) = compiled {
                fs::write(&args[2], compiled)?;
            }
            if let Some(output) = args.get(3) {
                fs::write(output, serde_json::to_vec(&info)?)?;
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            if let Some(receipt) = fenders_component::rejection_receipt(&wasm, &error) {
                if let Some(output) = args.get(3) {
                    fs::write(output, serde_json::to_vec(&receipt)?)?;
                }
                return Ok(ExitCode::from(2));
            }
            Err(error)
        }
    }
}
fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}
