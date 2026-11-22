#!/usr/bin/env python3
"""
Can the drift JUMP OVER the guard page?

The 1 MiB Singlepass stack sits above a 4 KiB guard page.  A drift of a few
bytes per iteration lands inside the guard page and is trapped cleanly.  But
the miscompilation skips an entire `add rsp, N` cleanup, where N is the size
of the block's stack slots.  If a single skipped cleanup is larger than the
4 KiB guard page, the stack pointer can land *below* the guard page, i.e. in
whatever the allocator placed under the wasm stack.

This script measures the landing point of the stack pointer relative to the
bottom of the writable wasm stack for different block shapes:

  * `body_pushes` = values left in the then-arm  -> larger `add rsp, N`
  * `ifs_per_iter` -> more blocks per iteration

It reports the offset (landing - stack_low).  Negative values mean "inside
the guard page"; values below -4096 mean "past the guard page".

Everything runs in a child process so a hard crash is observable as the
child's exit status instead of killing this script.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import crash_test as C                                  # noqa: E402


CHILD = r'''
import os, sys
sys.path.insert(0, %r)
import drift_fault as D
import crash_test as C

ifs  = int(sys.argv[1])
iters = int(sys.argv[2])
pushes = int(sys.argv[3])
call  = sys.argv[4]

wasm = C.build(ifs, iters, call == "1", pushes, 0, False)
D.run_wasm(wasm)
''' % HERE


def main():
    print("Buscando un salto que atraviese la pagina de guardia (4 KiB)")
    print("=" * 92)
    print("%-8s %-8s %-9s %-8s %s" % ("ifs", "pushes", "step(B)", "landing", "veredicto"))
    print("-" * 92)
    for ifs, pushes, iters in (
        (1, 0, 131072),
        (1, 8, 131072),
        (1, 64, 131072),
        (1, 512, 131072),
        (1, 1024, 131072),
        (1, 2048, 131072),
        (1, 4096, 131072),
        (1, 8192, 131072),
        (4, 1024, 32768),
        (4, 4096, 32768),
        (16, 1024, 8192),
    ):
        p = subprocess.run(
            [sys.executable, "-c", CHILD, str(ifs), str(iters), str(pushes), "1"],
            capture_output=True, text=True, timeout=600,
        )
        out = (p.stdout or "") + (p.stderr or "")
        landing = None
        for line in out.splitlines():
            if "landing" in line or "LANDING" in line:
                landing = line.strip()
        if p.returncode < 0:
            verdict = "MUERTO (rc=%d)" % p.returncode
        elif landing:
            verdict = landing
        else:
            verdict = (out.strip().splitlines() or ["sin salida"])[-1][:70]
        print("%-8d %-8d %-9d %-8s %s"
              % (ifs, pushes, ifs * (8 + 8 * pushes) // max(ifs, 1),
                 "-", verdict))
        sys.stdout.flush()


if __name__ == "__main__":
    main()
