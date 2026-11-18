#!/usr/bin/env bash
# A guest reads and writes no model-specific register, on this host's KVM: a
# VM under the launcher's filter (runtime/native/msr_filter.inc) faults on
# each read and write of four registers that a VM without it performs.
#
#   bash scripts/verify_msr_filter_live.sh
#
# Needs: Linux x86-64 with /dev/kvm, which it opens as root when the caller
# may not (passwordless sudo).
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
build=${TMPDIR:-/tmp}/fenders-msr-filter-$$
mkdir -p "$build"
trap 'rm -rf "$build"' EXIT
cc -O1 -g -Wall -Wextra -Werror "$repo/runtime/native/msr_filter_test.c" -o "$build/msr-filter-test"
if [[ -r /dev/kvm && -w /dev/kvm ]]; then "$build/msr-filter-test"; else sudo -n "$build/msr-filter-test"; fi
