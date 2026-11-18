#!/usr/bin/env bash
set -euo pipefail
task_root=$(cd "$(dirname "$0")/.." && pwd)
task_registry=${CARGO_HOME:-$HOME/.cargo}/registry
task_output=$task_root/.cache/demo-build
task_volume=${FENDERS_DEMO_BUILD_VOLUME:-fenders-demo-components-v1-target}
case "${1:---check}" in --check|--write) ;; *) echo 'usage: scripts/build_demos.sh [--check|--write]' >&2; exit 2;; esac
mkdir -p "$task_output"
# Canonical host, toolchain and paths avoid Cargo host-dependent module hashes.
# The first image build downloads only the pinned toolchain's WASI target.
docker build --platform linux/amd64 --tag fenders-demo-build:rust-1.90.0 - < "$task_root/examples/demo-components/Dockerfile"
docker run --rm --platform linux/amd64 --network none \
  -v "$task_root:/work:ro" -v "$task_registry:/cargo/registry:ro" \
  -v "$task_output:/out" -v "$task_volume:/target" \
  -w /work/examples/demo-components \
  -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/target -e CARGO_INCREMENTAL=0 \
  -e RUSTC_WRAPPER= -e CARGO_ENCODED_RUSTFLAGS=--remap-path-prefix=/work=/fenders \
  fenders-demo-build:rust-1.90.0 bash -c 'cargo +1.97.0 build --locked --offline --release --target wasm32-wasip2 && cp /target/wasm32-wasip2/release/hello-command.wasm /out/hello-command-v1.wasm && cp /target/wasm32-wasip2/release/fenders_demo_components.wasm /out/hello-http-v1.wasm'
for task_demo in hello-command-v1 hello-http-v1; do
  task_source="$task_output/$task_demo.wasm"
  task_dest="$task_root/crates/fenders-component/fixtures/$task_demo.wasm"
  if [[ ${1:---check} == --write ]]; then cp "$task_source" "$task_dest"; else cmp "$task_source" "$task_dest"; fi
done
