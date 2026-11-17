#!/usr/bin/env bash
# WASI filesystem semantics in fresh KVM guests, on the shipped runtime.
#
# Runs examples/service-client's filesystem probe through build/node's launcher
# and runtime with /app (read-only), /tmp and /data granted, and checks from the
# host that nothing outside the grants changed. Cases: all (create, exclusive
# open, truncate, positioned and streamed I/O, metadata, links, rename, escape
# attempts, cross-mount refusal), std (Rust std::fs), persist-read (a fresh VM
# reads the previous one's /data), none (no preopens) and missing-grant (a
# preopen with no VMM grant fails startup). Linux x86-64 with KVM only.
#
# Needs: scripts/build_node.sh, and build/examples/service-client.wasm from
# scripts/build_service_example.sh (or built elsewhere and copied in).
set -euo pipefail
task_root=$(cd "$(dirname "$0")/.." && pwd)
node="$task_root/build/node"
component="$task_root/build/examples/service-client.wasm"
for file in "$node/launch" "$node/runtime.elf" "$node/compile" "$component"; do
  [[ -e $file ]] || { echo "missing $file" >&2; exit 2; }
done
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
"$node/compile" "$component" "$work/client.cwasm"

# Lays out a sandbox: an asset, an outside directory the guest must never
# reach, and symlinks and a FIFO in /data that try to.
sandbox() {
  local dir=$1
  mkdir -p "$dir"/{app,tmp,data,outside}
  printf 'read-only asset\n' >"$dir/app/asset.txt"
  printf 'must remain outside the sandbox\n' >"$dir/outside/secret.txt"
  printf 'outside race canary\n' >"$dir/outside/attempt.txt"
  ln -s ../outside/secret.txt "$dir/data/escape-relative"
  ln -s "$dir/outside/secret.txt" "$dir/data/escape-absolute"
  mkfifo "$dir/data/blocked-fifo"
}

# Runs one case in a fresh VM; $3 is the /data grant (default the sandbox's).
launch() {
  local case=$1 dir=$2 data=${3:-$2/data}
  local env=(FENDERS_FS_APP="$dir/app" FENDERS_FS_TMP="$dir/tmp" FENDERS_FS_DATA="$data")
  [[ $case == missing-grant ]] && env=(FENDERS_FS_APP="$dir/app" FENDERS_FS_TMP="$dir/tmp")
  if [[ $case == none ]]; then
    printf 'FS_CASE=none\0' >"$dir/guest.env"
  else
    printf 'FS_CASE=%s\0FENDERS_FS_PREOPENS=/app,/tmp,/data\0' "$case" >"$dir/guest.env"
  fi
  local status=0
  env "${env[@]}" timeout 25 "$node/launch" "$node/runtime.elf" "$work/client.cwasm" "$dir/guest.env" \
    >"$dir/stdout" 2>"$dir/stderr" || status=$?
  echo "$status" >"$dir/status"
}

fail() { echo "FAIL filesystem $1: $2" >&2; sed 's/^/  stdout: /' "$3/stdout" >&2; sed 's/^/  stderr: /' "$3/stderr" | tail -20 >&2; exit 1; }

# What every case leaves untouched.
untouched() {
  local case=$1 dir=$2
  [[ $(cat "$dir/app/asset.txt") == 'read-only asset' ]] || fail "$case" "/app changed" "$dir"
  [[ $(cat "$dir/outside/secret.txt") == 'must remain outside the sandbox' ]] || fail "$case" "outside secret changed" "$dir"
  [[ $(cat "$dir/outside/attempt.txt") == 'outside race canary' ]] || fail "$case" "outside canary changed" "$dir"
  [[ $(ls "$dir/outside" | tr '\n' ' ') == 'attempt.txt secret.txt ' ]] || fail "$case" "outside gained entries" "$dir"
  [[ $(ls "$dir/app") == asset.txt ]] || fail "$case" "/app gained entries" "$dir"
}

verified() {
  local case=$1 dir=$2 checks=$3
  [[ $(cat "$dir/status") == 0 ]] || fail "$case" "exit $(cat "$dir/status")" "$dir"
  grep -q FENDERS_FILESYSTEM_VERIFIED "$dir/stdout" || fail "$case" "no verified marker" "$dir"
  [[ $(grep -c '^FENDERS_FS_CHECK ' "$dir/stdout" || true) == "$checks" ]] || fail "$case" "expected $checks checks" "$dir"
  untouched "$case" "$dir"
}

dir="$work/all"; sandbox "$dir"; launch all "$dir"
verified all "$dir" 6
[[ $(cat "$dir/tmp/ephemeral.txt") == 'ephemeral sandbox data' ]] || fail all "/tmp scratch file missing" "$dir"
[[ $(cat "$dir/data/created.txt") == 'hello filesystem' ]] || fail all "/data file missing" "$dir"
echo "PASS filesystem all: $(grep '^FENDERS_FS_CHECK ' "$dir/stdout" | cut -d' ' -f2 | tr '\n' ' ')"

reuse="$dir/data"
dir="$work/persist"; sandbox "$dir"; launch persist-read "$dir" "$reuse"
verified persist-read "$dir" 1
echo 'PASS filesystem persist-read: a fresh VM reads the previous VM'"'"'s /data'

dir="$work/std"; sandbox "$dir"; launch std "$dir"
verified std "$dir" 2
[[ ! -e $dir/data/std ]] || fail std "std tree not removed" "$dir"
[[ -z $(ls "$dir/tmp") ]] || fail std "/tmp not empty" "$dir"
echo 'PASS filesystem std: Rust std::fs create, copy, rename, seek, read_dir, remove_dir_all'

dir="$work/none"; sandbox "$dir"; launch none "$dir"
[[ $(cat "$dir/status") == 0 ]] && grep -q FENDERS_FILESYSTEM_VERIFIED "$dir/stdout" || fail none "no preopens case failed" "$dir"
untouched none "$dir"
echo 'PASS filesystem none: no preopens, no directories'

dir="$work/missing"; sandbox "$dir"; launch missing-grant "$dir"
[[ $(cat "$dir/status") != 0 ]] || fail missing-grant "started without a /data grant" "$dir"
! grep -q FENDERS_APP_READY "$dir/stdout" || fail missing-grant "app became ready" "$dir"
untouched missing-grant "$dir"
echo "PASS filesystem missing-grant: a preopen without a VMM grant fails startup (exit $(cat "$dir/status"))"
