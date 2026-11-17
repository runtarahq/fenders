#!/usr/bin/env bash
# A guest is refused KVM's paravirtual hypercalls, on this host's KVM: a
# vCPU set up as the launcher sets one up (runtime/native/vcpu_features.inc)
# asks for each and is told it is unknown, where one set up as KVM offers it
# is served.
#
#   bash scripts/verify_hypercalls_live.sh
#
# Needs: Linux x86-64 with /dev/kvm, which it opens as root when the caller
# may not (passwordless sudo).
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
build=${TMPDIR:-/tmp}/fenders-hypercalls-$$
mkdir -p "$build"
trap 'rm -rf "$build"' EXIT
cc -O1 -g -Wall -Wextra -Werror "$repo/runtime/native/hypercall_test.c" -o "$build/hypercall-test"
if [[ -r /dev/kvm && -w /dev/kvm ]]; then "$build/hypercall-test"; else sudo -n "$build/hypercall-test"; fi
