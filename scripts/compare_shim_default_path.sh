#!/usr/bin/env bash
# Shows that a change left the default launch path alone: runs the same
# component, with a spec that asks for nothing optional, under two builds of
# fenders-shim and launch, and compares what each did.
#
#   sudo scripts/compare_shim_default_path.sh BEFORE_DIR AFTER_DIR COMPONENT.cwasm ARTIFACT_SHA256 [OUT_DIR]
#
# Each DIR holds fenders-shim, launch and runtime.elf (root-owned, world
# readable, not under a private home). For each build it records, with
# `strace -f`, the calls the run channel's stub received and, for the shim
# and for the launcher apart, which system calls were made and the pipes
# and processes created. Counts that depend on timing (threads of the
# blocking pool, futex, epoll, reads and writes) are reported, not compared.
# Exits 1 if the stub's calls, either process's set of system calls, or the
# pipes, sockets and processes created differ. Needs what shim_standalone.sh needs, and strace.
set -euo pipefail
before=$1 after=$2 component=$3 artifact=$4
repo=$(cd "$(dirname "$0")/.." && pwd)
out=${5:-$(mktemp -d)}
mkdir -p "$out"

measure() { # NAME DIR
  local name=$1 dir=$2 wrap run tracer pid
  wrap=$(mktemp -d /var/lib/fenders-compare-XXXXXX)
  chmod 0755 "$wrap"
  # shim_standalone.sh starts DIR/fenders-shim: here, one that stops itself
  # before becoming the real shim, so strace can be attached from outside
  # the run's cgroup, where the shim must be alone.
  printf '#!/bin/sh\necho $$ > %s/pid\nkill -STOP $$\nexec %s/fenders-shim "$@"\n' "$wrap" "$dir" \
    > "$wrap/fenders-shim"
  chmod 0755 "$wrap/fenders-shim"
  bash "$repo/scripts/shim_standalone.sh" "$wrap" "$component" "$artifact" > "$out/$name.run" 2>&1 &
  run=$!
  for _ in $(seq 100); do [[ -s $wrap/pid ]] && break; sleep 0.1; done
  pid=$(cat "$wrap/pid")
  strace -f -qq -o "$out/$name.strace" -p "$pid" &
  tracer=$!
  sleep 1
  kill -CONT "$pid"
  wait "$run" || true
  wait "$tracer" 2>/dev/null || true
  rm -rf "$wrap"
  sed -n '/^--- stub calls/,$p' "$out/$name.run" | tail -n +2 |
    jq -c '{method, path, status, outcome}' > "$out/$name.calls"
  # The launcher is every process from the exec of launch on.
  awk -v launch="$dir/launch" -v shim="$out/$name.shim" -v vmm="$out/$name.launch" '
    { pid=$1; line=$0; sub(/^[0-9]+ +/, "", line) }
    index(line, "execve(\"" launch "\"") { launcher[pid]=1 }
    /clone|fork/ && launcher[pid] { if (match(line, /= [0-9]+$/)) launcher[substr(line, RSTART+2)]=1 }
    # A call split by strace into "unfinished" and "resumed" is counted once.
    line ~ /^<\.\.\. / { next }
    { name=line; sub(/\(.*/, "", name)
      if (name ~ /^[a-z_0-9]+$/) print name > (launcher[pid] ? vmm : shim) }' "$out/$name.strace"
  for part in shim launch; do
    sort "$out/$name.$part" | uniq -c | awk '{print $2, $1}' > "$out/$name.$part.counts"
    cut -d' ' -f1 "$out/$name.$part.counts" > "$out/$name.$part.set"
    grep -E '^(pipe2?|socketpair|socket|fork|vfork|execve|memfd_create|eventfd2?) ' \
      "$out/$name.$part.counts" > "$out/$name.$part.created" || true
  done
}

measure before "$before"
measure after "$after"
status=0
for part in calls shim.set launch.set shim.created launch.created; do
  if diff -u "$out/before.$part" "$out/after.$part" > "$out/$part.diff"; then
    echo "same     $part ($(wc -l < "$out/before.$part") lines)"
  else
    echo "DIFFERS  $part"; cat "$out/$part.diff"; status=1
  fi
done
echo "--- system calls made (before / after), for information"
for part in shim launch; do
  echo "$part threads: $(grep -E "^clone3? " "$out/before.$part.counts" | awk "{n+=\$2} END {print n+0}") / $(grep -E "^clone3? " "$out/after.$part.counts" | awk "{n+=\$2} END {print n+0}")"
  echo "$part: $(awk '{n+=$2} END {print n}' "$out/before.$part.counts") / $(awk '{n+=$2} END {print n}' "$out/after.$part.counts")"
done
echo "details in $out"
exit $status
