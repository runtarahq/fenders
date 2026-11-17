#!/usr/bin/env bash
# Builds the guest vDSO (vdso.c) as DIR/vdso.so. launch.c embeds it with
# `.incbin "vdso.so"`, so compile launch.c with -Wa,-IDIR after this.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?usage: build_vdso.sh DIR}
mkdir -p "$out"
"${CC:-cc}" -O2 -fPIC -shared -nostdlib -fno-stack-protector -fno-asynchronous-unwind-tables \
  -fcf-protection=none -Wall -Wextra -Werror -I"$here" \
  -Wl,-T,"$here/vdso.ld" -Wl,--hash-style=both -Wl,--no-undefined \
  -Wl,-soname=linux-vdso.so.1 -Wl,--version-script="$here/vdso.lds" \
  "$here/vdso.c" -o "$out/vdso.so"
