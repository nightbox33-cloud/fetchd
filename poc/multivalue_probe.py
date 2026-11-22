#!/usr/bin/env python3
"""
Multi-value `if` blocks: allowed by CosmWasm v3?  and are the values correct?

The upstream regression test (wasmerio/wasmer @ e5ca9b938,
tests/compilers/issues.rs::implicit_else_reclaims_inputs) covers
`param_count in [0, 1, 2]`.  With two parameters the block type is
`(param i64 i64) (result i64 i64)`, and `Operator::If` then runs

    allocate_return_slots_and_swap(param_types.len() + 1, return_types.len())
    = allocate_return_slots_and_swap(3, 2)

so TWO native slots are reserved per `if` and the parameter relocation is a
3->2 shuffle instead of a 2->1 one.

CosmWasm v3 rejects contracts whose *function* type has more than one result
(`max_function_results() == 1`), but a block type that points at a two-result
function type lives in the same type section.  This script checks:

  1. whether the VM accepts such a module at all (store_code),
  2. if it does: how many bytes each iteration leaks,
  3. whether the values the block produces are the correct ones.
"""
import os
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                                     # noqa: E402
from wasm_builder import (                              # noqa: E402
    Module, I32, I64, op_i32_const, op_i64_const, op_nop, op_end, op_if,
    op_drop, op_local_get, op_local_set, op_local_tee, op_i32_sub, op_loop,
    op_br_if, op_call, op_i32_store, op_i32_add, op_global_get, op_global_set,
    op_i64_add,
)

RESP_PTR = 16
RESP_DATA = 64
PV1 = 0x0123456789ABCDEF
PV2 = 0xFEDCBA9876543210


def op_i64_store(offset=0, align=3):
    return b"\x37" + bytes([align]) + bytes([offset])


def build(params, iterations, prefix=4, then_values=(999, 888)):
    """`params` = number of parameters/results of the `if` block type."""
    m = Module()
    m.add_memory(4, export="memory")
    t_pass = m.add_type([I64] * params, [I64] * params)
    m.add_data(RESP_PTR, RESP_DATA.to_bytes(4, "little") + (16).to_bytes(4, "little")
               + (16).to_bytes(4, "little"))
    m.add_data(RESP_DATA, b"\x00" * 16)
    probe = m.add_func([], [], body=op_nop())

    b = bytearray()
    b += op_i64_const(PV1) + op_local_set(0)
    b += op_i64_const(PV2) + op_local_set(1)
    b += op_i32_const(0) + op_local_set(2)        # condition
    b += op_i32_const(iterations) + op_local_set(3)

    b += op_loop()
    for _ in range(prefix):
        b += op_local_get(0)
    for p in range(params):
        b += op_local_get(p)                     # the block parameters
    b += op_local_get(2)                         # the condition
    b += op_if(t_pass)
    b += op_drop() * params
    for v in then_values[:params]:
        b += op_i64_const(v)                     # the then-branch
    b += op_end()                                # implicit else
    b += op_drop() * prefix
    b += op_drop() * params                      # drop the results
    b += op_call(probe)
    b += op_local_get(3) + op_i32_const(1) + op_i32_sub() + op_local_tee(3) + op_br_if(0)
    b += op_end()

    # publish local0 and local1 so we can see whether the values survived
    b += op_i32_const(RESP_DATA) + op_local_get(0) + op_i64_store()
    b += op_i32_const(RESP_DATA + 8) + op_local_get(1) + op_i64_store()

    fn = m.add_func([], [], locals=[I64, I64, I32, I32], body=bytes(b))
    m.add_func([I32, I32, I32], [I32], body=op_call(fn) + op_i32_const(RESP_PTR),
               export="execute")
    m.add_func([I32, I32, I32], [I32], body=op_i32_const(RESP_PTR),
               export="instantiate")
    m.add_func([], [], body=op_nop(), export="interface_version_8")
    g_bump = m.add_global(I32, True, op_i32_const(1024))
    g_region = m.add_global(I32, True, op_i32_const(128))
    alloc = (
        op_global_get(g_region) + op_local_set(1)
        + op_local_get(1) + op_global_get(g_bump) + op_i32_store()
        + op_local_get(1) + op_i32_const(4) + op_i32_add() + op_local_get(0) + op_i32_store()
        + op_local_get(1) + op_i32_const(8) + op_i32_add() + op_i32_const(0) + op_i32_store()
        + op_global_get(g_bump) + op_local_get(0) + op_i32_add() + op_global_set(g_bump)
        + op_global_get(g_region) + op_i32_const(12) + op_i32_add() + op_global_set(g_region)
        + op_local_get(1)
    )
    m.add_func([I32], [I32], locals=[I32], body=alloc, export="allocate")
    m.add_func([I32], [], body=op_nop(), export="deallocate")
    return m.build()


def run(wasm, gas_limit=1 << 62):
    base = tempfile.mkdtemp()
    vm = R.VM()
    try:
        cache = vm.init_cache(base)
        checksum = vm.store_code(cache, wasm, checked=True)
    except Exception as exc:                            # noqa: BLE001
        return None, "REJECTED: %s" % str(exc)[:200]
    vm.instantiate(cache, checksum, gas_limit)
    res, rep, err = vm.execute(cache, checksum, gas_limit)
    errtxt = vm._vec_str(err)
    if errtxt:
        return None, errtxt.replace("\n", " ")[:150]
    raw = vm._vec_bytes(res)
    if len(raw) < 16:
        return None, "respuesta corta %r" % raw
    v1, v2 = struct.unpack("<qq", raw[:16])
    return (v1, v2, rep.used_internally), None


def threshold(params, prefix=4):
    """Smallest iteration count that exhausts the native stack."""
    lo, hi = 1, 400000
    r, _ = run(build(params, hi, prefix))
    if r is None:
        return None
    while lo < hi:
        mid = (lo + hi) // 2
        r, e = run(build(params, mid, prefix))
        if r is None and "call stack exhausted" in (e or ""):
            hi = mid
        else:
            lo = mid + 1
    return lo


def main():
    print("Bloques `if` multi-resultado en CosmWasm v3 (produccion v3.0.8-rc.3)")
    print("=" * 92)
    for params in (1, 2, 3):
        wasm = build(params, 3)
        got, err = run(wasm)
        if err and err.startswith("REJECTED"):
            print("params=%d  -> %s" % (params, err))
            continue
        if err:
            print("params=%d  -> error en ejecucion: %s" % (params, err))
            continue
        v1, v2, gas = got
        th = threshold(params)
        leak = (1048576.0 / th) if th else 0
        print("params=%d  ACEPTADO   valores=[%s, %s]  gas=%d" %
              (params, hex(v1 & 0xFFFFFFFFFFFFFFFF), hex(v2 & 0xFFFFFFFFFFFFFFFF), gas))
        print("           umbral de agotamiento de pila = %s iteraciones  ->  %.1f B/iter"
              % (th, leak))
        print("           valores esperados = [%s, %s]  ->  %s"
              % (hex(PV1), hex(PV2),
                 "OK" if (v1 & 0xFFFFFFFFFFFFFFFF) == PV1
                 and (v2 & 0xFFFFFFFFFFFFFFFF) == PV2 else "*** VALORES MAL ***"))


if __name__ == "__main__":
    main()
