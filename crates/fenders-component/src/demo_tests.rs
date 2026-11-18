//! Execute the shipped examples through real WASI bindings. This native-engine
//! check does not qualify kernel-free guest execution or fleet startup latency.
use super::*;
use http_body_util::{BodyExt, Full};
use wasmtime_wasi::{WasiCtxBuilder, p2::pipe::MemoryOutputPipe};
const COMMAND: &[u8] = include_bytes!("../fixtures/hello-command-v1.wasm");
const HTTP: &[u8] = include_bytes!("../fixtures/hello-http-v1.wasm");
fn store(engine: &Engine) -> (wasmtime::Store<Host>, MemoryOutputPipe) {
    let stdout = MemoryOutputPipe::new(4096);
    let host = Host {
        wasi: WasiCtxBuilder::new().stdout(stdout.clone()).build(),
        http: WasiHttpCtx::new(),
        table: ResourceTable::new(),
    };
    let mut store = wasmtime::Store::new(engine, host);
    store.set_fuel(10_000_000).unwrap();
    (store, stdout)
}
fn linker(engine: &Engine) -> Linker<Host> {
    let mut linker = Linker::new(engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker).unwrap();
    wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker).unwrap();
    linker
}
#[tokio::test]
async fn bundled_command_runs_only_when_invoked_and_prints_greeting() {
    let info = inspect(COMMAND).unwrap();
    assert!(info.command && !info.http);
    let engine = Engine::new(&config()).unwrap();
    let component = Component::new(&engine, COMMAND).unwrap();
    let (mut store, stdout) = store(&engine);
    let command = wasmtime_wasi::p2::bindings::Command::instantiate_async(
        &mut store,
        &component,
        &linker(&engine),
    )
    .await
    .unwrap();
    assert!(
        stdout.contents().is_empty(),
        "initializing does not run the command"
    );
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        command.wasi_cli_run().call_run(&mut store),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(stdout.contents().as_ref(), b"Hello from Fenders.\n");
}
#[tokio::test]
async fn bundled_http_handles_a_real_wasi_request_without_outgoing_access() {
    use wasmtime_wasi_http::p2::bindings::{ProxyPre, http::types::Scheme};
    let info = inspect(HTTP).unwrap();
    assert!(info.http && !info.command);
    assert!(
        !info
            .imports
            .iter()
            .any(|name| name.contains("outgoing-handler") || name.starts_with("wasi:sockets/"))
    );
    let engine = Engine::new(&config()).unwrap();
    let component = Component::new(&engine, HTTP).unwrap();
    let pre = ProxyPre::new(linker(&engine).instantiate_pre(&component).unwrap()).unwrap();
    let (mut store, stdout) = store(&engine);
    let request = hyper::Request::builder()
        .uri("http://demo.invalid/")
        .body(Full::new(bytes::Bytes::new()).map_err(|never| -> hyper::Error { match never {} }))
        .unwrap();
    let (send, receive) = tokio::sync::oneshot::channel();
    let input = store
        .data_mut()
        .http()
        .new_incoming_request(Scheme::Http, request)
        .unwrap();
    let output = store.data_mut().http().new_response_outparam(send).unwrap();
    let handler = async {
        let proxy = pre.instantiate_async(&mut store).await.unwrap();
        proxy
            .wasi_http_incoming_handler()
            .call_handle(&mut store, input, output)
            .await
            .unwrap();
    };
    let response = async {
        let response = receive.await.unwrap().unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.headers()["content-type"],
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .as_ref(),
            b"Hello from Fenders.\n"
        );
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(handler, response);
    })
    .await
    .unwrap();
    assert_eq!(stdout.contents().as_ref(), b"HTTP request completed.\n");
}
