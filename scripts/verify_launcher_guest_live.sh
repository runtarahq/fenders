#!/usr/bin/env bash
# The launcher, tested from inside its VM on this host's KVM: a small
# freestanding guest (runtime/native/guest_probe.c) is booted in place of
# the Wasmtime runtime, makes the calls a hostile or unusual guest would,
# and the launcher's exit status and messages are checked for each scenario.
#
#   bash scripts/verify_launcher_guest_live.sh
#
# Scenarios:
#   files        a host file's identity is not the guest's to learn; advice
#                that drops its cache is not done; a file mapping holds the
#                file, a refused one leaves nothing; an unknown call is said
#                once in the launcher's messages
#   thread       a thread made just before its parent exits keeps the run
#   last-thread  the last thread's exit is the guest's, status 0
#   pointer      a pointer outside the guest ends it with status 3
#   sockets      sockets are made at a bounded rate
#   msr          reading a model-specific register ends the guest, status 3
#   descriptors  every descriptor the launcher holds while its guest runs,
#                the sockets and pipes it inherited among them, closes on
#                exec, and the guest's threads are confined by its own filter
# Needs: Linux x86-64 with /dev/kvm, passwordless sudo (to open /dev/kvm
# when the caller may not, and to look at a running launcher), cc, python3,
# and `scripts/build_node.sh` already run.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
launch=$repo/build/node/launch
[[ -x $launch ]] || { echo "missing $launch" >&2; exit 2; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cc -O1 -Wall -Wextra -Werror -ffreestanding -nostdlib -static -fno-pie -no-pie -fno-stack-protector \
  -mno-red-zone -mgeneral-regs-only "$repo/runtime/native/guest_probe.c" -o "$work/probe.elf"
chmod -R a+rX "$work"
run=()
[[ -r /dev/kvm && -w /dev/kvm ]] || run=(sudo -n)
failed=0
scenario() {
  local name=$1 status=$2 says=$3 actual=0
  printf 'PROBE=%s\0' "$name" > "$work/env"
  "${run[@]}" env -i FENDERS_LIFETIME_SECONDS=20 "$launch" "$work/probe.elf" "$work/probe.elf" "$work/env" \
    > "$work/out" 2> "$work/messages" || actual=$?
  if [[ $actual == "$status" ]] && grep -q -- "$says" "$work/messages"; then
    echo "PASS $name: launcher status $actual, \"$says\""
  else
    echo "FAIL $name: launcher status $actual (wanted $status, \"$says\")"; sed 's/^/    /' "$work/messages" | tail -5
    failed=1
  fi
}
scenario files 0 'guest exit 0'
[[ $(grep -c 'unsupported syscall 9999' "$work/messages") == 1 ]] ||
  { echo 'FAIL files: an unknown call was not said exactly once'; failed=1; }
scenario thread 1 'guest exit 7'
scenario last-thread 0 'every thread exited'
scenario pointer 3 'invalid guest pointer'
scenario sockets 0 'sockets and connections refused'
scenario msr 3 'unexpected KVM exit'
# The launcher with the sockets and pipes a shim hands it, looked at from
# outside while its guest spins.
printf 'PROBE=spin\0' > "$work/env"
# As root whoever may open /dev/kvm: the launcher is not dumpable, and what
# it holds is then root's alone to list.
sudo -n python3 - "$launch" "$work/probe.elf" "$work/env" <<'PY' || failed=1
import os, socket, subprocess, sys, time
launch, probe, env_file = sys.argv[1:]
pairs = [socket.socketpair() for _ in range(3)]
hold_read, hold_write = os.pipe()
meter_read, meter_write = os.pipe()
names = ["FENDERS_CONTROL_FD", "FENDERS_INGRESS_FD", "FENDERS_HOST_ORIGIN_FD"]
env = {name: str(pair[0].fileno()) for name, pair in zip(names, pairs)}
env.update(FENDERS_HOLD_FD=str(hold_read), FENDERS_METER_FD=str(meter_write), FENDERS_LIFETIME_SECONDS="20")
given = [pair[0].fileno() for pair in pairs] + [hold_read, meter_write]
child = subprocess.Popen([launch, probe, probe, env_file], env=env, pass_fds=given,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    time.sleep(1.0)
    assert child.poll() is None, "the launcher did not stay up"
    kept = []
    for fd in sorted(map(int, os.listdir(f"/proc/{child.pid}/fd"))):
        if fd <= 2:
            continue
        flags = next(int(line.split()[1], 8) for line in open(f"/proc/{child.pid}/fdinfo/{fd}") if line.startswith("flags:"))
        if not flags & 0o2000000:
            kept.append((fd, os.readlink(f"/proc/{child.pid}/fd/{fd}")))
    assert not kept, f"descriptors that would survive an exec: {kept}"
    assert set(given) <= set(map(int, os.listdir(f"/proc/{child.pid}/fd"))), "an inherited descriptor is gone"
    # Every thread, the guest's among them, runs under two filters: the
    # launcher's own is on all of them.
    filters = {open(f"/proc/{child.pid}/task/{task}/status").read().split("Seccomp_filters:")[1].split()[0]
               for task in os.listdir(f"/proc/{child.pid}/task")}
    assert filters == {"1"}, f"filters per thread: {filters}"
    print("PASS descriptors: all of the launcher's close on exec, the five it inherited among them; its own filter is on every thread")
finally:
    child.kill(); child.wait()
PY
exit "$failed"
