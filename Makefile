SHELL := /bin/bash
.DEFAULT_GOAL := build

.PHONY: build build-platform run test verify verify-platform check build-node build-demos build-service-example verify-network-native verify-confinement verify-compiler-confinement clean
build: build-platform
build-platform:
	cargo build --workspace --release --locked
run:
	cargo run --locked -p fenders-control-plane -- --state run/platform-dev --dev-http --port 19090
check:
	cargo fmt --check
	cargo clippy --workspace --all-targets --locked -- -D warnings
# Tests run as CI runs them: more threads at once exhaust a stock
# PostgreSQL's locks and slow the tests that keep time.
test verify: verify-platform
verify-platform:
	@test -n "$$FENDERS_TEST_DATABASE_URL" || (echo 'Set FENDERS_TEST_DATABASE_URL to a dedicated PostgreSQL database' >&2; exit 1)
	cargo test --workspace --locked -- --test-threads=4
build-node:
	bash scripts/build_node.sh
build-demos:
	bash scripts/build_demos.sh
build-service-example:
	bash scripts/build_service_example.sh
verify-network-native:
	bash scripts/verify_network_native.sh
verify-confinement:
	target/release/fenders-confinement-test
verify-compiler-confinement:
	@test -n "$(CONFINEMENT_CGROUP)" || (echo 'Set CONFINEMENT_CGROUP to an empty delegated test cgroup root' >&2; exit 1)
	target/release/fenders-compiler-test build/node/compile "$(CONFINEMENT_CGROUP)" build/node/example-command.wasm build/node/example-http.wasm
clean:
	rm -rf build
