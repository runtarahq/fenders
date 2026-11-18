# Example components

The sources of two small components, a command and an HTTP handler, kept as
built `.wasm` files in `crates/fenders-component/fixtures/`. The component
crate's tests compile and inspect them, so that what a real toolchain produces
is what the compiler is tested against.

They are examples and test fixtures. The control plane ships none of them and
offers no way to pick one: a product built on Fenders uploads whatever it
wants its users to start from, as it uploads anything else.

## Rebuilding

```sh
cargo fetch --locked --manifest-path examples/demo-components/Cargo.toml
scripts/build_demos.sh --check
```

The default mode rebuilds offline, in a pinned container, and compares the
bytes with the committed files; `--write` replaces them. A change to the
sources is committed together with the rebuilt files.
