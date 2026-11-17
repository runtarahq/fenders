#!/usr/bin/env bash
# A cgroup limited to a run's destinations reaches them and nothing else, on
# this host's kernel: the listed address and port, the resolver's port 53,
# and a refusal for the same port on another address, other ports, other
# datagram destinations and IPv6.
#
#   bash scripts/verify_destinations_live.sh
#
# Runs crates/fenders-node/tests/destination_limits.rs as root, which the
# programs take to load. Needs: Linux with cgroup v2, passwordless sudo, and
# 127.0.0.53:53 or 127.0.0.77:53 free for the test's resolver.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"
binary=$(cargo test -p fenders-node --locked --test destination_limits --no-run --message-format=json 2>/dev/null |
  jq -r 'select(.target.name? == "destination_limits" and .executable != null) | .executable' | tail -1)
[[ -x $binary ]] || { echo 'the test did not build' >&2; exit 2; }
sudo -n "$binary" | tee /dev/stderr | grep -q '^test result: ok'
