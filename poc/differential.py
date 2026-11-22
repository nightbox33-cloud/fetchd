#!/usr/bin/env python3
"""
Differential test of the Singlepass "implicit else" code path.

Per the WebAssembly specification, an `if` without an `else` that has block
parameters is *defined* as

    if (param t*) (result t*)  <then>  end
    == if (param t*) (result t*)  <then>  else  end

i.e. the implicit else arm is the identity on the block parameters.  Any
divergence between the two forms is a miscompilation.

This script builds both forms of the same module, executes them through the
production CosmWasm C ABI and compares the produced values.

Usage:
    python3 differential.py [--iters N] [--stack N] [--prefixes 0,4,31,32]
"""
import argparse
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                      # noqa: E402
from wasm_builder import (               # noqa: E402
    Module, I32, I64, op_i32_const, op_i64_const, op_nop, op_end, op_if, op_else,
    op_drop, op_call, op_local_get, op_local_set, op_local_tee, op_i32_sub,
    op_br, op_br_if, op_unreachable, op_i32_eq, op_loop, op_block, op_i64_add,
    op_i64_const, op_global_get, op_global_set,
)

# then-arm bodies; each must leave exactly `param_count` i64 values
BODIES = ["empty", "replace", "add", "nested-if", "block", "call", "brif", "unreach"]


def build(param_count, prefix_count, body, explicit, iterations, cond):
    m = Module()
    m.add_memory(2, export="memory")
    t_pass = m.add_type([I64] * param_count, [I64] * param_count)

    g_val = m.add_global(I64, True, op_i64_const(0))
    probe = m.add_func([], [], body=op_nop())

    b = bytearray()
    b += op_i32_const(iterations) + op_local_set(2)
    b += op_loop()
    for _ in range(prefix_count + param_count):
        b += op_local_get(0)          # local.get $value
    b += op_local_get(1)              # local.get $condition
    b += op_if(t_pass)
    if body == "replace":
        b += (op_drop() + op_i64_const(42)) * param_count
    elif body == "add":
        for _ in range(param_count):
            b += op_local_get(0) + op_i64_add()   # sum of two i64 operands
    elif body == "nested-if":
        b += op_i32_const(1) + op_if() + op_nop() + op_end()
    elif body == "block":
        b += op_block() + op_nop() + op_end()
    elif body == "call":
        b += op_call(probe)
    elif body == "brif":
        b += op_i32_const(0) + op_br_if(0)
    elif body == "unreach":
        b += op_unreachable()
    if explicit:
        b += op_else()               # identity: the block params fall through
    b += op_end()
    b += op_global_set(g_val)        # consume one result
    for _ in range(param_count - 1):
        b += op_drop()
    for _ in range(prefix_count):
        b += op_drop()
    b += op_call(probe)
    b += op_local_get(2) + op_i32_const(1) + op_i32_sub() + op_local_tee(2) + op_br_if(0)
    b += op_end()
    b += op_global_get(g_val)
    check = m.add_func([I64, I32], [I64], locals=[I32], body=bytes(b))

    m.add_func([I32], [I32], body=op_i32_const(1024), export="allocate")
    m.add_func([I32], [], body=op_nop(), export="deallocate")
    m.add_func([I32, I32, I32], [I32], body=op_i32_const(16), export="instantiate")
    # execute: call check(123, cond) and return the 8 raw bytes as the payload
    m.add_data(16, (64).to_bytes(4, "little") + (8).to_bytes(4, "little")
               + (8).to_bytes(4, "little"))
    m.add_data(1024, (2048).to_bytes(4, "little") + (4096).to_bytes(4, "little")
               + (0).to_bytes(4, "little"))
    ex = (op_i64_const(123) + op_i32_const(cond) + op_call(check) + op_local_set(3)
          + op_i32_const(64) + op_local_get(3) + b"\x37\x03\x00"   # i64.store @64
          + op_i32_const(16))
    m.add_func([I32, I32, I32], [I32], locals=[I64], body=ex, export="execute")
    m.add_func([], [], body=op_nop(), export="interface_version_8")
    return m.build()


def run(wasm, stack_size):
    base = tempfile.mkdtemp(prefix="wasmvm-diff-")
    vm = R.VM()
    cache = vm.init_cache(base)
    checksum = vm.store_code(cache, wasm, checked=True)
    res, rep, err = vm.instantiate(cache, checksum, 1 << 62)
    if res.is_none:
        return ("INSTANTIATE-ERR", R.VM._vec_str(err)[:120], None)
    res2, rep2, err2 = vm.execute(cache, checksum, 1 << 62)
    e = R.VM._vec_str(err2)
    if e:
        return ("ERROR", e[:150], None)
    data = R.VM._vec_bytes(res2)
    val = int.from_bytes(data[:8], "little") if len(data) >= 8 else None
    return ("OK", "", val)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=1)
    ap.add_argument("--stack", type=int, default=1 << 20)
    ap.add_argument("--prefixes", default="0,4,31,32")
    ap.add_argument("--params", default="1")
    args = ap.parse_args()
    prefixes = [int(x) for x in args.prefixes.split(",")]
    params_list = [int(x) for x in args.params.split(",")]

    print("differential: implicit-else  vs  explicit-else(identity)   iters=%d"
          % args.iters)
    print("%-6s %-8s %-10s %-6s %-22s %-22s %s"
          % ("param", "prefix", "body", "cond", "implicit", "explicit", "verdict"))
    diffs = 0
    total = 0
    for param in params_list:
        for prefix in prefixes:
            for body in BODIES:
                for cond in (0, 1):
                    a = build(param, prefix, body, False, args.iters, cond)
                    b = build(param, prefix, body, True, args.iters, cond)
                    sa, ea, va = run(a, args.stack)
                    sb, eb, vb = run(b, args.stack)
                    total += 1
                    if sa == "OK" and sb == "OK":
                        verdict = "same(%d)" % va if va == vb else \
                                 "*** DIFFER: %r vs %r ***" % (va, vb)
                        if va != vb:
                            diffs += 1
                    else:
                        verdict = "*** DIFFER: %s/%s vs %s/%s ***" % (sa, ea[:40], sb, eb[:40])
                        diffs += 1
                    print("%-6d %-8d %-10s %-6d %-22s %-22s %s"
                          % (param, prefix, body, cond,
                             "%s%s" % (sa, "" if sa != "OK" else ":%r" % va),
                             "%s%s" % (sb, "" if sb != "OK" else ":%r" % vb),
                             verdict))
                    sys.stdout.flush()
    print()
    print("cases=%d  divergences=%d" % (total, diffs))
    return 1 if diffs else 0


if __name__ == "__main__":
    sys.exit(main())
