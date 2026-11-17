#!/usr/bin/env bash
set -euo pipefail
task_root=$(cd "$(dirname "$0")/.." && pwd)
export CC_wasm32_wasip2=${CC_wasm32_wasip2:-clang}
export CFLAGS_wasm32_wasip2=${CFLAGS_wasm32_wasip2:---sysroot=/usr -isystem /usr/include/wasm32-wasi}
cd "$task_root/examples/service-client"
cargo +1.97.0 build --locked --release --target wasm32-wasip2
mkdir -p "$task_root/build/examples"
cp target/wasm32-wasip2/release/fenders-http-component.wasm "$task_root/build/examples/service-client.wasm"
