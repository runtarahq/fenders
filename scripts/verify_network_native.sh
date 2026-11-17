#!/usr/bin/env bash
set -euo pipefail
task_root=$(cd "$(dirname "$0")/.." && pwd)
task_build=$(mktemp -d)
trap 'rm -rf "$task_build"' EXIT
# Linux native sockets only. This never claims KVM guest or cross-host testing.
cc -pthread -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
  "$task_root/runtime/native/network_test.c" -o "$task_build/network-test"
timeout 15 "$task_build/network-test"
timeout 15 "$task_build/network-test" --budget
timeout 15 "$task_build/network-test" --budget-wait
timeout 15 "$task_build/network-test" --meter
timeout 60 "$task_build/network-test" --meter-final
cc -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
  "$task_root/runtime/native/guest_args_test.c" -o "$task_build/guest-args-test"
"$task_build/guest-args-test"
task_status=0
timeout 15 "$task_build/network-test" --leases 2>/dev/null || task_status=$?
if [[ $task_status != 2 ]]; then
  echo "launch accepted a network lease (status $task_status)" >&2
  exit 1
fi
echo 'PASS network leases are refused'
if [[ $(uname -m) == x86_64 ]]; then
  bash "$task_root/runtime/native/build_vdso.sh" "$task_build/vdso"
  cc -pthread -O2 -Wall -Wextra -Werror -Wa,-I"$task_build/vdso" \
    "$task_root/runtime/native/launch.c" -o "$task_build/launch"
elif command -v x86_64-linux-gnu-gcc >/dev/null; then
  CC=x86_64-linux-gnu-gcc bash "$task_root/runtime/native/build_vdso.sh" "$task_build/vdso"
  x86_64-linux-gnu-gcc -pthread -O2 -Wall -Wextra -Werror -Wa,-I"$task_build/vdso" \
    "$task_root/runtime/native/launch.c" -o "$task_build/launch"
else
  echo 'The x86-64 VMM compilation check requires x86_64-linux-gnu-gcc and libc6-dev-amd64-cross.' >&2
  exit 2
fi
if [[ $(uname -m) == x86_64 ]]; then
  cc -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
    "$task_root/runtime/native/cpuid_test.c" -o "$task_build/cpuid-test"
  "$task_build/cpuid-test"
fi
echo 'PASS x86-64 VMM compile (not a KVM execution test)'
# The launcher's own messages: standard error unless a pipe is named for them.
task_plain=$("$task_build/launch" 2>&1 >/dev/null || true)
task_error=$( { FENDERS_DIAGNOSTICS_FD=3 "$task_build/launch" 3> >(cat > "$task_build/diagnostics") 2>&1 >/dev/null || true; } )
sleep 0.2
task_status=0
FENDERS_DIAGNOSTICS_FD=3 "$task_build/launch" 3>"$task_build/not-a-pipe" 2>/dev/null || task_status=$?
if [[ $task_plain != usage:* || -n $task_error || $(cat "$task_build/diagnostics") != "$task_plain" || $task_status != 2 ]]; then
  echo "launcher diagnostics descriptor: plain='$task_plain' stderr='$task_error' status=$task_status" >&2
  exit 1
fi
echo 'PASS launcher messages go to FENDERS_DIAGNOSTICS_FD when named, else standard error'
