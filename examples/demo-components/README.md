# Fenders demo components

These are the sources for the two components bundled with the customer deployment
wizard. They require no external network connections, secrets or mounted files.

- **HTTP hello:** a WASI HTTP incoming handler returns status 200,
  `text/plain; charset=utf-8`, and `Hello from Fenders.\n`. It prints
  `HTTP request completed.\n` after finishing the response.
- **Hello command:** a WASI CLI command prints `Hello from Fenders.\n` and exits
  successfully. It supports manual and scheduled invocation.

Selection uploads the bundled bytes into the chosen project using ordinary
storage admission and compiler inspection. It does not create an app or invoke a
command. After deployment, explicitly send an HTTP sample request or run the
command to observe its output. Compilation/inspection is not evidence of a live VM.

Build with Docker and the checked-in digest-pinned Rust 1.97.0 Linux/amd64 image.
The first image build downloads its `wasm32-wasip2` standard library. Application
compilation has networking disabled and uses the host Cargo registry read-only.
Populate missing sources, then check the bundle:

```sh
cargo fetch --locked --manifest-path examples/demo-components/Cargo.toml
scripts/build_demos.sh --check
```

The default mode rebuilds offline and compares bytes with the bundled `.wasm`
files. `--write` regenerates the bundle during development. The script remaps the
workspace path and strips symbol/debug information. The canonical host architecture,
toolchain and paths are intentional: native macOS and Linux builds were observed
to differ in Cargo module hashes and function ordering. To verify a clean build,
set `FENDERS_DEMO_BUILD_VOLUME` to a fresh Docker volume name. Source formatting can change embedded
panic locations, so regenerate after formatting. Commit source, lockfile and
bundled bytes together. Changes to a published example require a new demo version;
do not silently replace an existing version's content. Requests pin the listed
source digest, so mixed API revisions cannot substitute another component.

Native Wasmtime tests inspect and execute the shipped binaries through real WASI
bindings, verify the HTTP body and command output, and confirm command initialization
produces no output. Those checks do not replace live kernel-free VM qualification.
