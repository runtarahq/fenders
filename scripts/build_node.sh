#!/usr/bin/env bash
set -euo pipefail
task_root=$(cd "$(dirname "$0")/.." && pwd)
[[ $(uname -sm) == 'Linux x86_64' ]] || { echo 'Build on Linux x86-64.' >&2; exit 2; }
mkdir -p "$task_root/build/node"
cd "$task_root/runtime/guest"
cargo +1.97.0 rustc --locked --release --target x86_64-unknown-linux-musl -- -C relocation-model=static
cp target/x86_64-unknown-linux-musl/release/fenders-http-runtime "$task_root/build/node/runtime.elf"
cd "$task_root/runtime/native"
bash build_vdso.sh "$task_root/build/vdso"
# Hardening named here, not left to the distribution compiler's defaults.
cc -pthread -O2 -Wall -Wextra -Werror -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fPIE -pie \
  -Wl,-z,relro,-z,now,-z,noexecstack -Wa,-I"$task_root/build/vdso" launch.c -o "$task_root/build/node/launch"
cd "$task_root/examples/runtime-fixtures"
cargo +1.97.0 build --locked --release --target wasm32-wasip2
cp target/wasm32-wasip2/release/fenders-command.wasm "$task_root/build/node/example-command.wasm"
cp target/wasm32-wasip2/release/fenders-dual.wasm "$task_root/build/node/example-dual.wasm"
cp target/wasm32-wasip2/release/fenders_node_fixtures.wasm "$task_root/build/node/example-http.wasm"
cp target/wasm32-wasip2/release/fenders-public-https.wasm "$task_root/build/node/example-public-https.wasm"
cd "$task_root/examples/async-fixture"
cargo +1.97.0 build --locked --release --target wasm32-wasip2
cp target/wasm32-wasip2/release/fenders_async_fixture.wasm "$task_root/build/node/example-async.wasm"
cd "$task_root/examples/async-http-fixture"
cargo +1.97.0 build --locked --release --target wasm32-wasip2
cp target/wasm32-wasip2/release/fenders_async_http_fixture.wasm "$task_root/build/node/example-async-http.wasm"
cd "$task_root"
cargo +1.97.0 build --workspace --locked --release
cp target/release/fenders-component "$task_root/build/node/compile"
cp target/release/fenders-node target/release/fenders-node-server target/release/fendersctl target/release/fenders-shim "$task_root/build/node/"
cd "$task_root/build/node"
sha256sum runtime.elf launch compile fenders-node fenders-node-server fendersctl fenders-shim example-command.wasm example-http.wasm example-public-https.wasm example-dual.wasm example-async.wasm example-async-http.wasm > SHA256SUMS
