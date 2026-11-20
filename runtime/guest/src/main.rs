//! Upstream Wasmtime HTTP runtime. The native platform supplies its ABI services.
use wasmtime::{Config,Engine,Store};
use fenders_runtime_limits::AggregateLimits;
use wasmtime::component::{Component,Linker,ResourceTable};
use wasmtime_wasi::{WasiCtx,WasiCtxView,WasiView,FsPerms};
use wasmtime_wasi_http::{RequestOptions,WasiBody,WasiHttpCtx,WasiHttpCtxView,WasiHttpHooks,WasiHttpView};

// musl's allocator takes each small group from mmap and returns it with
// munmap almost at once, and every one of those is a VM exit (~350 per run):
// dlmalloc takes memory in large chunks and keeps it.
#[global_allocator]
static ALLOCATOR: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

struct State { wasi:WasiCtx, http:WasiHttpCtx, table:ResourceTable, limits:AggregateLimits, policy:HttpPolicy }

/// The launch's outgoing HTTP policy. Every `wasi:http` version sends through
/// these hooks, so the same origins bind 0.2 and 0.3 requests.
struct HttpPolicy { allowed:Vec<String>, deny:bool, host:Option<String> }
impl WasiView for State {
    fn ctx(&mut self)->WasiCtxView<'_> {WasiCtxView{ctx:&mut self.wasi,table:&mut self.table}}
}
impl WasiHttpView for State {
    fn http(&mut self)->WasiHttpCtxView<'_> {
        WasiHttpCtxView{ctx:&mut self.http,table:&mut self.table,hooks:&mut self.policy}
    }
}
type SendIo=Box<dyn std::future::Future<Output=wasmtime_wasi_http::Result<()>>+Send>;
impl WasiHttpHooks for HttpPolicy {
    fn send_request(&mut self,request:hyper::Request<WasiBody>,options:Option<RequestOptions>,io:SendIo)
        ->Box<dyn std::future::Future<Output=wasmtime_wasi_http::Result<(hyper::Response<WasiBody>,SendIo)>>+Send> {
        let _=io;
        let tls=request.uri().scheme()==Some(&hyper::http::uri::Scheme::HTTPS);
        let scheme=if tls {"https"} else {"http"};
        let origin=request.uri().authority().filter(|a|!a.as_str().contains('@')).map(|a|format!("{scheme}://{}:{}",a.host().to_ascii_lowercase(),a.port_u16().unwrap_or(if tls {443} else {80})));
        // The host-bound origin needs no grant; it reaches the node, never the network.
        if origin.is_some() && origin==self.host {
            return Box::new(async move {
                Ok((host_origin::send(request).await?,Box::new(async {Ok(())}) as SendIo))
            });
        }
        if self.deny || !origin.is_some_and(|o|self.allowed.contains(&o)) {
            return Box::new(async {Err(wasmtime_wasi_http::Error::HttpRequestDenied)});
        }
        Box::new(async move {
            use http_body_util::BodyExt;
            let (response,io)=fenders_guest_http::send_request(request,options).await?;
            Ok((response.map(BodyExt::boxed_unsync),Box::new(io) as SendIo))
        })
    }
}
fn main()->anyhow::Result<()> {
    println!("FENDERS_UPSTREAM_BOOT");
    // Keep the bounded blocking worker for the lifetime of a resident service;
    // the native platform has a fixed virtual-thread inventory.
    let runtime=tokio::runtime::Builder::new_current_thread().max_blocking_threads(1)
        .thread_keep_alive(std::time::Duration::from_secs(86400)).enable_all().build()?;
    runtime.block_on(async {
        let mut config=Config::new();
        config.wasm_component_model_async(true).signals_based_traps(false).memory_reservation(0).memory_guard_size(0)
            .memory_reservation_for_growth(0).memory_init_cow(false).consume_fuel(true);
        // A deeply recursing guest (a compiler, say) is given more host stack;
        // its async stack holds that and the host's own frames above it.
        if let Ok(stack)=std::env::var("FENDERS_WASM_STACK_BYTES") {
            let stack:usize=stack.parse()?;
            config.max_wasm_stack(stack).async_stack_size(stack+1024*1024);
        }
        let engine=Engine::new(&config)?;
        let mut linker=Linker::<State>::new(&engine);
        wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
        wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)?;
        // WASI 0.3 alongside 0.2: the same views, and the same HTTP hooks.
        wasmtime_wasi::p3::add_to_linker(&mut linker)?;
        wasmtime_wasi_http::p3::add_to_linker(&mut linker)?;
        if std::env::var("FENDERS_MODE").as_deref()==Ok("http") {
            return service::serve(&engine, &linker).await;
        }
        if let Some(path)=std::env::args().nth(1) {
            // Only operator-produced artifacts from the pinned compiler are trusted.
            let component=unsafe{Component::deserialize_file(&engine,path)?};
            // Everything up to here depends on the component alone, so a warm
            // launch does it before its run is known (see `go`).
            let pre=linker.instantiate_pre(&component)?;
            let succeeded=if component.get_export_index(None,"wasi:cli/run@0.3.0").is_some() {
                // A WASI 0.3 command: `run` is lifted async and runs as a task.
                let pre=wasmtime_wasi::p3::bindings::CommandPre::new(pre)?;
                go()?;
                let mut store=make_store(&engine)?;
                let command=pre.instantiate_async(&mut store).await?;
                store.run_concurrent(async move |store| command.wasi_cli_run().call_run(store).await).await??.is_ok()
            } else {
                let pre=wasmtime_wasi::p2::bindings::CommandPre::new(pre)?;
                go()?;
                let mut store=make_store(&engine)?;
                let command=pre.instantiate_async(&mut store).await?;
                command.wasi_cli_run().call_run(&mut store).await?.is_ok()
            };
            anyhow::ensure!(succeeded,"WASI command failed");
            println!("FENDERS_COMPONENT_COMPLETE");
        } else {
            make_store(&engine)?;
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        println!("FENDERS_UPSTREAM_LINKED");
        Ok::<(),anyhow::Error>(())
    })
}

/// Waits for the run, when the launch is warm: the VMM holds the open of
/// `/fenders/go` until the shim is claimed for a run, and returns what the
/// shim sent with it: `NAME=value` entries, each NUL-terminated, that join the
/// environment. A launch that is not warm has no such file and runs at once.
fn go()->anyhow::Result<()> {
    let bytes=match std::fs::read("/fenders/go") {
        Ok(bytes)=>bytes,
        Err(error) if error.kind()==std::io::ErrorKind::NotFound=>return Ok(()),
        Err(error)=>return Err(anyhow::anyhow!("waiting for the run: {error}")),
    };
    for entry in bytes.split(|b|*b==0).filter(|e|!e.is_empty()) {
        let entry=std::str::from_utf8(entry).map_err(|_|anyhow::anyhow!("run environment is not UTF-8"))?;
        let (name,value)=entry.split_once('=').ok_or_else(|| anyhow::anyhow!("run environment entry without ="))?;
        anyhow::ensure!(!name.is_empty(),"run environment entry without a name");
        // Before the store exists the runtime reads no environment elsewhere,
        // and its one other thread (the blocking worker) reads none.
        unsafe{std::env::set_var(name,value)};
    }
    Ok(())
}

/// The app sees its configuration and the documented run context, never the
/// runtime's own policy (`FENDERS_HTTP_ALLOW`, `FENDERS_FUEL` and the rest).
/// Configuration cannot define `FENDERS_*` names, so this is an exact allowlist.
const RUN_CONTEXT:&[&str]=&["FENDERS_TRIGGER","FENDERS_TRIGGER_TIME","FENDERS_RUN_ID","FENDERS_SCHEDULE","FENDERS_SCHEDULE_TIMEZONE"];
fn app_visible(name: &str) -> bool {
    !name.starts_with("FENDERS_") || RUN_CONTEXT.contains(&name)
}
fn setting(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}
fn make_store(engine: &Engine) -> anyhow::Result<Store<State>> {
        let mut wasi=WasiCtx::builder();
        wasi.inherit_stdout().inherit_stderr().allow_tcp(true).allow_udp(false).allow_ip_name_lookup(false);
        for (name,value) in std::env::vars().filter(|(name,_)|app_visible(name)) { wasi.env(name,value); }
        // Preopens are an operator configuration. The VMM independently grants
        // the corresponding host directories and enforces read-only mounts.
        for name in std::env::var("FENDERS_FS_PREOPENS").unwrap_or_default().split(',').filter(|s|!s.is_empty()) {
            let perms=match name {
                "/app"=>FsPerms::ReadOnly,
                "/tmp"|"/data"=>FsPerms::ReadWrite,
                _=>anyhow::bail!("unsupported filesystem preopen"),
            };
            wasi.preopened_dir(name,name,perms)?;
        }
        let socket_allow:Vec<std::net::SocketAddr>=std::env::var("FENDERS_SOCKET_ALLOW").unwrap_or_default().split(',').filter_map(|s|s.parse().ok()).collect();
        // Connecting a socket the guest did not bind, wasmtime first asks whether it may be bound to the
        // unspecified address, and binds nothing: without that answer no TCP connection can be made. A bind
        // the guest asks for itself reaches the launcher, which refuses it for a TCP socket.
        wasi.socket_addr_check(move |addr,reason| {use wasmtime_wasi::sockets::SocketAddrUse;let allowed=match reason {
            SocketAddrUse::TcpConnect=>socket_allow.contains(&addr),
            SocketAddrUse::TcpBind=>addr.ip().is_unspecified() && addr.port()==0,
            _=>false};Box::pin(async move {allowed})});
        let mut store=Store::new(engine,State{wasi:wasi.build(),http:WasiHttpCtx::new(),table:ResourceTable::new(),
            limits:AggregateLimits::with_structure(usize::try_from(setting("FENDERS_WASM_MEMORY_BYTES", 4*1024*1024))?,
                usize::try_from(setting("FENDERS_INSTANCES", 32))?,usize::try_from(setting("FENDERS_TABLE_ELEMENTS", 10_000))?,
                usize::try_from(setting("FENDERS_TABLES", 16))?,usize::try_from(setting("FENDERS_MEMORIES", 32))?),
            policy:HttpPolicy{
                allowed:std::env::var("FENDERS_HTTP_ALLOW").unwrap_or_default().split(',').map(str::to_owned).collect(),
                deny:std::env::var("FENDERS_HTTP_DENY").as_deref()==Ok("1"), host:host_origin::origin() } });
        // Refuelling on yield leaves the run bounded by its lifetime alone. It yields every 10,000,000 units
        // rather than every 10,000: a yield costs far more in the VM than natively, and a compute-bound run (a
        // compiler, say) spent most of its time yielding; the host's tasks still run every few milliseconds.
        let refuel=std::env::var("FENDERS_FUEL_REFUEL").as_deref()==Ok("yield");
        let fuel=if refuel {u64::MAX} else {setting("FENDERS_FUEL", 200_000_000)};
        store.limiter(|s|&mut s.limits);store.set_fuel(fuel)?;
        store.fuel_async_yield_interval(Some(if refuel {10_000_000} else {10_000}))?;
    Ok(store)
}
mod host_origin;
mod service;

#[cfg(test)]
mod tests {
    use super::app_visible;
    #[test]
    fn apps_see_configuration_and_run_context_but_not_runtime_policy() {
        for name in ["DATABASE_URL","PGHOST","FENDERS_TRIGGER","FENDERS_TRIGGER_TIME","FENDERS_RUN_ID","FENDERS_SCHEDULE","FENDERS_SCHEDULE_TIMEZONE"] {
            assert!(app_visible(name),"{name}");
        }
        for name in ["FENDERS_MODE","FENDERS_FUEL","FENDERS_FUEL_REFUEL","FENDERS_HOST_ORIGIN","FENDERS_INSTANCES","FENDERS_TABLE_ELEMENTS","FENDERS_TABLES","FENDERS_MEMORIES","FENDERS_HTTP_ALLOW","FENDERS_HTTP_SERVICE_ROOTS","FENDERS_HTTP_PUBLIC_TARGETS","FENDERS_SOCKET_ALLOW","FENDERS_WASM_MEMORY_BYTES","FENDERS_WASM_STACK_BYTES","FENDERS_REQUEST_TIMEOUT_MS","FENDERS_HTTP_CONCURRENCY","FENDERS_HTTP_STREAM_MS","FENDERS_FS_PREOPENS","FENDERS_HTTP_DENY","FENDERS_SCHEDULE_X"] {
            assert!(!app_visible(name),"{name}");
        }
    }
}
