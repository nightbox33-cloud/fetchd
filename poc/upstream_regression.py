#!/usr/bin/env python3
"""
Faithful re-implementation of the upstream Wasmer regression test

    wasmerio/wasmer @ e5ca9b93809d744af8b33488a748a284d3d41955
    tests/compilers/issues.rs::implicit_else_reclaims_inputs

executed against the *production* libwasmvm artifact that fetchd links
(priv_wasmvm_sec v3.0.8-rc.3 -> Wasmer 7.4.2 Singlepass).

The upstream test is written in WAT; this script rebuilds the identical
module byte-for-byte in Wasm (same opcode sequence) and drives it through
the CosmWasm C ABI of the production .so.

Upstream WAT (verbatim from the commit):

    (module
      (type $pass (func (param i64...) (result i64...)))
      (func $probe)
      (func (export "check")
        (param $value i64) (param $condition i32) (param $expected i64)
        (result i32) (local $remaining i32)
        i32.const 400000 local.set $remaining
        loop
          {pushes}                       ; local.get $value  x (prefix+param)
          local.get $condition
          if {block_type} {body} {else_text} end
          {checks}                       ; (local.get $expected i64.ne if unreachable end) x param
          {drops}                        ; drop x prefix
          call $probe
          local.get $remaining i32.const 1 i32.sub
          local.tee $remaining br_if 0
        end
        i32.const 1))

Usage:
    python3 upstream_regression.py [--stack N] [--iters N] [--matrix]
"""
import argparse
import ctypes
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                      # noqa: E402
from wasm_builder import (               # noqa: E402
    Module, I32, I64, op_i32_const, op_i64_const, op_nop, op_end, op_if, op_else,
    op_drop, op_call, op_local_get, op_local_set, op_local_tee, op_i32_sub,
    op_i64_ne, op_br, op_br_if, op_unreachable, op_i32_eq, op_loop, op_block,
)

RESP = b'{"ok":{"messages":[],"attributes":[],"events":[],"data":null}}'

# upstream body variants: (name, body_kind, explicit_else, true_reachable, true_result)
BODIES = [
    ("empty", "empty", False, True, 123),
    ("replace", "replace", False, True, 42),
    ("branch", "branch", False, True, 123),
    ("unreachable", "unreachable", False, False, 123),
    ("nested-unreachable", "nested-unreachable", False, False, 123),
    ("explicit-else", "replace", True, True, 42),
]


def build_upstream(param_count, prefix_count, body_kind, explicit_else, iterations,
                   with_probe=True, condition=0, expected=123):
    """Rebuilds the upstream regression module in raw Wasm."""
    m = Module()
    m.add_memory(2, export="memory")

    if param_count:
        t_pass = m.add_type([I64] * param_count, [I64] * param_count)
        block_type = t_pass
    else:
        t_pass = None
        block_type = 0x40

    # static response region (offset 16 -> payload at 64) and allocator region
    m.add_data(16, (64).to_bytes(4, "little") + len(RESP).to_bytes(4, "little")
               + len(RESP).to_bytes(4, "little"))
    m.add_data(64, RESP)
    m.add_data(1024, (2048).to_bytes(4, "little") + (4096).to_bytes(4, "little")
               + (0).to_bytes(4, "little"))

    probe = m.add_func([], [], body=op_nop())

    # ---- func check (param $value i64, $condition i32, $expected i64) -> i32
    b = bytearray()
    b += op_i32_const(iterations) + op_local_set(3)      # local $remaining
    b += op_loop()
    for _ in range(prefix_count + param_count):           # {pushes}
        b += op_local_get(0)
    b += op_local_get(1)                                  # local.get $condition
    if param_count:
        b += op_if(t_pass)
    else:
        b += op_if()
    if body_kind == "replace":
        b += (op_drop() + op_i64_const(42)) * param_count
    elif body_kind == "branch":
        b += op_br(0)
    elif body_kind == "unreachable":
        b += op_unreachable()
    elif body_kind == "nested-unreachable":
        b += op_unreachable()
    if explicit_else:
        # upstream's explicit-else case has an EMPTY else arm: the value that
        # falls through the block is the one that must be checked.
        b += op_else()
        if body_kind != "replace" or not param_count:
            b += op_nop()
    b += op_end()
    for _ in range(param_count):                          # {checks}
        b += op_local_get(2) + op_i64_ne() + op_if() + op_unreachable() + op_end()
    for _ in range(prefix_count):                         # {drops}
        b += op_drop()
    if with_probe:
        b += op_call(probe)
    b += op_local_get(3) + op_i32_const(1) + op_i32_sub() + op_local_tee(3) + op_br_if(0)
    b += op_end()
    b += op_i32_const(1)
    check = m.add_func([I64, I32, I64], [I32], locals=[I32], body=bytes(b))

    # ---- cosmwasm ABI surface
    m.add_func([I32], [I32], body=op_i32_const(1024), export="allocate")
    m.add_func([I32], [], body=op_nop(), export="deallocate")
    m.add_func([I32, I32, I32], [I32], body=op_i32_const(16), export="instantiate")

    # execute -> calls check(123, condition, expected); traps if the result != 1
    ex = bytearray()
    ex += op_block()
    ex += op_i64_const(123) + op_i32_const(condition) + op_i64_const(expected)
    ex += op_call(check)
    ex += op_i32_const(1) + op_i32_eq()
    ex += op_br_if(0)          # result == 1 -> leave the block
    ex += op_unreachable()      # result != 1 -> trap (visible)
    ex += op_end()
    ex += op_i32_const(16)
    m.add_func([I32, I32, I32], [I32], body=bytes(ex), export="execute")
    m.add_func([], [], body=op_nop(), export="interface_version_8")
    return m.build()


def run_case(wasm, stack_size, gas_limit=1 << 62):
    """Runs one module on a thread with a controlled native stack."""
    r = R.run_once(wasm, stack_size, gas_limit=gas_limit)
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stack", type=int, default=1 << 20)
    ap.add_argument("--iters", type=int, default=400000)
    ap.add_argument("--matrix", action="store_true")
    ap.add_argument("--param", type=int, default=1)
    ap.add_argument("--prefix", type=int, default=4)
    ap.add_argument("--body", default="empty")
    ap.add_argument("--explicit", action="store_true")
    ap.add_argument("--no-probe", action="store_true")
    args = ap.parse_args()

    if args.matrix:
        print("stack=%d  iterations=%d" % (args.stack, args.iters))
        print("%-20s %-6s %-7s %-8s %-14s %s"
              % ("body", "param", "prefix", "result", "gas", "detail"))
        for body_name, kind, explicit, _, _ in BODIES:
            for param_count in (0, 1, 2):
                for prefix_count in (0, 4, 31, 32):
                    wasm = build_upstream(param_count, prefix_count, kind,
                                          explicit, args.iters, with_probe=not args.no_probe)
                    r = run_case(wasm, args.stack)
                    detail = ""
                    err = (r.get("execute_err") or r.get("instantiate_err")
                           or r.get("store_err") or "")
                    if err:
                        detail = err.replace("\n", " ")[:95]
                    low = err.lower()
                    if r.get("crashed"):
                        verdict = "CRASH"
                    elif r.get("store_err"):
                        verdict = "REJECTED"
                    elif "call stack exhausted" in low:
                        verdict = "STACK-EXH"
                    elif "unreachable" in low:
                        verdict = "VALUE-BAD"
                    elif "out of bounds" in low:
                        verdict = "MEM-OOB"
                    elif err:
                        verdict = "ERR"
                    else:
                        verdict = "ok"
                    print("%-20s %-6d %-7d %-8s %-14s %s"
                          % (body_name, param_count, prefix_count, verdict,
                             r.get("gas", ""), detail))
                    sys.stdout.flush()
        return

    wasm = build_upstream(args.param, args.prefix, args.body, args.explicit, args.iters,
                         with_probe=not args.no_probe)
    r = run_case(wasm, args.stack)
    print("param=%d prefix=%d body=%s explicit=%s iters=%d stack=%d"
          % (args.param, args.prefix, args.body, args.explicit, args.iters, args.stack))
    print("checksum : %s" % r["checksum"])
    print("crashed  : %s (rc=%s)" % (r.get("crashed"), r.get("rc")))
    print("gas      : %s" % r.get("gas"))
    print("err      : %s" % r.get("err"))
    print("stdout   : %s" % r.get("stdout", "").strip()[:400])
    print("stderr   : %s" % r.get("stderr", "").strip()[:400])


if __name__ == "__main__":
    main()
