#!/usr/bin/env python3
"""
Faithful re-implementation of the upstream Wasmer regression test

    wasmerio/wasmer @ e5ca9b93809d744af8b33488a748a284d3d41955
    tests/compilers/issues.rs::implicit_else_reclaims_inputs

executed against the *production* libwasmvm artifact that fetchd links
(priv_wasmvm_sec v3.0.8-rc.3 -> Wasmer 7.4.2, Singlepass).

The upstream test is written in WAT; this script rebuilds the identical
module in raw Wasm (same opcode sequence) and drives it through the
CosmWasm C ABI of the production .so.

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

Two properties of the upstream test matter and are preserved here:

  * the {checks} block compares every block result against $expected and
    traps with `unreachable` on mismatch -> it is a *value* oracle;
  * the {body} of the `explicit-else` case is EMPTY upstream (the else
    arm does not replace the value), so `explicit-else` is the control
    case: it exercises the same inputs through the `Operator::Else`
    path, which upstream's fix routes the implicit else through too.

A run therefore separates two very different failures:

  VALUE-CORRUPTION : the {checks} oracle traps -> the guest computed a
                      wrong value (integrity problem);
  STACK-LEAK       : the guest traps with "call stack exhausted" after
                      many iterations -> the native stack grew instead
                      of being reclaimed (availability problem).

Usage:
    python3 upstream_faithful.py --matrix
    python3 upstream_faithful.py --body empty --param 1 --prefix 4 --iters 400000
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                                      # noqa: E402
from wasm_builder import (                               # noqa: E402
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
                   condition=0, with_probe=True, expected=None):
    """Rebuilds the upstream regression module in raw Wasm.

    `condition` selects which arm of the `if` is taken at run time and
    `expected` is the value the guest must produce for it.  With
    condition=0 the false arm runs (the implicit-else path that leaks);
    with condition=1 the true arm runs.
    """
    if expected is None:
        expected = 123

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
        # upstream's explicit-else case has an EMPTY else arm: the value
        # that falls through the block is the one that must be checked.
        b += op_else()
        if body_kind == "replace" and param_count:
            # upstream: the else arm of `explicit-else` is empty; keep the
            # value that was already on the stack.
            pass
        else:
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


def classify(r):
    """Turns the harness dict into a verdict that separates value
    corruption from stack exhaustion."""
    if r.get("store_err"):
        return "REJECTED"
    if r.get("crashed"):
        return "CRASH"
    if r.get("exception"):
        return "HARNESS-ERR"
    if r.get("instantiate_err"):
        return "INST_ERR"
    err = (r.get("execute_err") or "").lower()
    if err:
        if "call stack exhausted" in err:
            return "STACK-EXH"
        if "unreachable" in err:
            return "VALUE-BAD"
        if "out of bounds" in err:
            return "MEM-OOB"
        if "out of gas" in err:
            return "OUT-OF-GAS"
        return "ERR"
    if r.get("resp") is not None:
        return "ok"
    return "?"


def detail(r):
    err = (r.get("execute_err") or r.get("instantiate_err")
           or r.get("store_err") or "")
    return err[:88].replace("\n", " ")


def cmd_matrix(args):
    print("Upstream regression matrix (faithful port) on the production .so")
    print("stack=%d bytes  iterations=%d  condition=%d" % (args.stack, args.iters,
                                                          args.condition))
    print()
    print("%-19s %-5s %-6s %-11s %-14s %s"
          % ("body", "param", "prefix", "verdict", "gas", "detail"))
    print("-" * 112)
    for body_name, kind, explicit, true_reachable, true_result in BODIES:
        for param_count in (0, 1, 2):
            for prefix_count in (0, 4, 31, 32):
                # upstream iterates `for condition in 0..=i32::from(true_reachable)`:
                # bodies whose true arm traps are only exercised with
                # condition=0, because condition=1 would legitimately trap
                # inside the body rather than expose a miscomputation.
                conds = (0, 1) if true_reachable else (0,)
                for condition in conds:
                    expected = 123 if condition == 0 else true_result
                    wasm = build_upstream(param_count, prefix_count, kind,
                                          explicit, args.iters,
                                          condition=condition, expected=expected)
                    r = R.run_once(wasm, args.stack, gas_limit=args.gas_limit)
                    print("%-19s %-5d %-6d %-11s %-14s %s"
                          % (body_name, param_count, prefix_count, classify(r),
                             r.get("gas", "-"), detail(r)))
                    sys.stdout.flush()


def cmd_boundary(args):
    """The value oracle fires on the FIRST iteration if the value is wrong.
    Walking the iteration count across the exhaustion threshold therefore
    separates the two failure modes unambiguously:
      * wrong value   -> trap 'unreachable' at iteration 1 (gas ~700k)
      * stack leak    -> trap 'call stack exhausted' only at ~131k iters
    """
    print("Boundary between value corruption and stack exhaustion")
    print("shape: param=1 prefix=4, condition=0 (false arm / implicit else)")
    print()
    print("%-12s %-12s %-18s %s" % ("iterations", "verdict", "gas", "detail"))
    print("-" * 100)
    for iters in (1, 2, 100, 1000, 10000, 100000, 130000, 131000, 131028,
                  131029, 131100, 200000, 400000):
        wasm = build_upstream(1, 4, "empty", False, iters, condition=0,
                              expected=123)
        r = R.run_once(wasm, args.stack, gas_limit=args.gas_limit)
        print("%-12d %-12s %-18s %s" % (iters, classify(r), r.get("gas", "-"),
                                        detail(r)))
        sys.stdout.flush()


def cmd_case(args):
    wasm = build_upstream(args.param, args.prefix, args.body, args.explicit,
                          args.iters, condition=args.condition, expected=args.expected)
    r = R.run_once(wasm, args.stack, gas_limit=args.gas_limit)
    print("param=%d prefix=%d body=%s explicit=%s iters=%d condition=%d stack=%d"
          % (args.param, args.prefix, args.body, args.explicit, args.iters,
             args.condition, args.stack))
    print("verdict   : %s" % classify(r))
    print("checksum  : %s" % r.get("checksum"))
    print("gas       : %s" % r.get("gas"))
    print("err       : %s" % detail(r))
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stack", type=int, default=1 << 20)
    ap.add_argument("--iters", type=int, default=400000)
    ap.add_argument("--gas-limit", type=int, default=1 << 62)
    ap.add_argument("--matrix", action="store_true")
    ap.add_argument("--param", type=int, default=1)
    ap.add_argument("--prefix", type=int, default=4)
    ap.add_argument("--body", default="empty")
    ap.add_argument("--explicit", action="store_true")
    ap.add_argument("--condition", type=int, default=0)
    ap.add_argument("--expected", type=int, default=123)

    ap.add_argument("--boundary", action="store_true")
    args = ap.parse_args()

    if args.matrix:
        cmd_matrix(args)
    elif args.boundary:
        cmd_boundary(args)
    else:
        cmd_case(args)


if __name__ == "__main__":
    main()
