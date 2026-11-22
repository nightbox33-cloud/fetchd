#!/usr/bin/env python3
"""
INTEGRITY experiment for the Singlepass "implicit else" miscompilation.

Question: the defect exhausts the native stack.  Does it ALSO compute wrong
values (which would let a contract mis-account funds), or does it only leak
stack slots (availability)?

This script answers that with a differential oracle that needs no reference
compiler:

  * the module under test uses the EXACT upstream regression shape
    (block type `(param i64) (result i64)`, prefix=4 so the block parameter
    really spills to the native stack -- i.e. the configuration that leaks);
  * the same module is built twice: once with the implicit `else` (the
    miscompiled path) and once with an EXPLICIT `else` that forwards the
    parameter -- which is exactly what the WebAssembly specification
    mandates an implicit `else` to do;
  * the value produced by the `if` is written back to linear memory and read
    out of the CosmWasm response.

Any difference between the two builds is a miscalculation the contract can
observe.  The iteration count is kept below the exhaustion threshold so that
a stack leak cannot mask a value error (or vice versa).

Additionally the script reads back four sentinel locals that live on the
native stack, to detect clobbering of the spilled slots.

Measured on the production libwasmvm artifact (priv_wasmvm_sec v3.0.8-rc.3).
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
    op_else, op_drop, op_local_get, op_local_set, op_local_tee, op_i32_sub,
    op_loop, op_br_if, op_call, op_i32_store, op_i32_add, op_global_get,
    op_global_set, op_i64_add,
)

RESP_PTR = 16
RESP_DATA = 64
SENT = [0x1111111111111111, 0x2222222222222222,
        0x3333333333333333, 0x4444444444444444]
PV = 0x0123456789ABCDEF
THEN_VALUE = 999


def op_i64_store(offset=0, align=3):
    return b"\x37" + bytes([align]) + bytes([offset])


def build(explicit_else, cond, iterations, prefix, call_after):
    """Returns 16 bytes: [0..8) the value produced by the last `if`,
    [8..16) the sum of four sentinel locals that live on the native stack."""
    m = Module()
    m.add_memory(4, export="memory")
    t_pass = m.add_type([I64], [I64])
    m.add_data(RESP_PTR, RESP_DATA.to_bytes(4, "little") + (16).to_bytes(4, "little")
               + (16).to_bytes(4, "little"))
    m.add_data(RESP_DATA, b"\x00" * 16)

    probe = m.add_func([], [], body=op_nop())

    b = bytearray()
    # locals: 0 = param(i64) 1 = cond(i32) 2 = counter(i32) 3 = scratch(i64)
    #         4..7 = sentinels (index > 3 -> they live on the native stack)
    for i, v in enumerate(SENT):
        b += op_i64_const(v) + op_local_set(4 + i)
    b += op_i64_const(PV) + op_local_set(0)
    b += op_i32_const(cond) + op_local_set(1)
    b += op_i32_const(iterations) + op_local_set(2)

    b += op_loop()
    for _ in range(prefix):
        b += op_local_get(0)
    b += op_local_get(0)              # the block parameter
    b += op_local_get(1)              # the condition
    b += op_if(t_pass)
    b += op_drop() + op_i64_const(THEN_VALUE)      # then-branch
    if explicit_else:
        # the explicit else forwards the parameter, exactly like the implicit
        # else is specified to do
        b += op_else()
        b += op_drop() + op_local_get(0)
    b += op_end()
    # The block result sits ON TOP of the stack; the prefix values are below
    # it.  The result must therefore be captured BEFORE the prefix values are
    # dropped, otherwise the drops would remove the result itself and the
    # probe would measure the wrong value (and could never detect a
    # difference between the implicit and the explicit else).
    b += op_local_tee(3) + op_drop()
    for _ in range(prefix):
        b += op_drop()
    b += op_local_get(2) + op_i32_const(1) + op_i32_sub() + op_local_tee(2) + op_br_if(0)
    b += op_end()

    if call_after:
        b += op_call(probe)

    b += (op_local_get(4) + op_local_get(5) + op_i64_add()
          + op_local_get(6) + op_local_get(7) + op_i64_add() + op_i64_add()
          + op_local_set(8))
    b += op_i32_const(RESP_DATA) + op_local_get(3) + op_i64_store()
    b += op_i32_const(RESP_DATA + 8) + op_local_get(8) + op_i64_store()

    # 0=param 1=cond 2=counter 3=result 4..7=sentinels 8=sentinel sum
    fn = m.add_func([], [], locals=[I64, I32, I32, I64, I64, I64, I64, I64, I64],
                    body=bytes(b))
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


def run(wasm):
    """Returns (verdict, value, sentinel_sum)."""
    base = tempfile.mkdtemp()
    vm = R.VM()
    cache = vm.init_cache(base)
    checksum = vm.store_code(cache, wasm, checked=True)
    res, rep, err = vm.instantiate(cache, checksum, 1 << 62)
    if res.is_none:
        return "INST_ERR", None, None
    res2, rep2, err2 = vm.execute(cache, checksum, 1 << 62)
    errtxt = vm._vec_str(err2)
    if errtxt:
        low = errtxt.lower()
        if "call stack exhausted" in low:
            return "STACK-EXH", None, None
        if "unreachable" in low:
            return "VALUE-BAD", None, None
        return "ERR", None, None
    blob = vm._vec_bytes(res2)
    if len(blob) < 16:
        return "SHORT-RESP", None, None
    val, sent = struct.unpack_from("<QQ", blob, 0)
    return "ok", val, sent


def main():
    print("INTEGRITY: implicit else vs explicit else (spec-equivalent control)")
    print("shape: block type (param i64)(result i64), prefix=4 (parameter spills)")
    print()
    print("%-8s %-6s %-8s %-11s %-12s %-12s %-18s %s"
          % ("iters", "cond", "call", "variant", "value", "sentinels", "verdict", "diff"))
    print("-" * 118)

    for iterations in (1, 100, 10000, 100000):
        for cond in (0, 1):
            for call_after in (False, True):
                res = {}
                for name, explicit in (("implicit", False), ("explicit", True)):
                    wasm = build(explicit, cond, iterations, 4, call_after)
                    res[name] = run(wasm)
                iv, isent = res["implicit"][1], res["implicit"][2]
                ev, esent = res["explicit"][1], res["explicit"][2]
                same_v = (iv == ev) if iv is not None and ev is not None else None
                same_s = (isent == esent) if isent is not None and esent is not None else None
                diff = "n/a"
                if same_v is not None:
                    diff = "value:%s sent:%s" % ("same" if same_v else "DIFF",
                                                "same" if same_s else "DIFF")
                print("%-8d %-6d %-8s %-11s %-12s %-12s %-18s %s"
                      % (iterations, cond, call_after,
                         "implicit", hex(iv) if iv is not None else "-",
                         hex(isent) if isent is not None else "-",
                         res["implicit"][0], diff))
                print("%-8s %-6s %-8s %-11s %-12s %-12s %-18s %s"
                      % ("", "", "", "explicit", hex(ev) if ev is not None else "-",
                         hex(esent) if esent is not None else "-",
                         res["explicit"][0], ""))
                sys.stdout.flush()

    print()
    print("Reference values")
    print("  block parameter  PV        = %s" % hex(PV))
    print("  then-branch value         = %s" % hex(THEN_VALUE))
    print("  sentinels sum             = %s" % hex(sum(SENT) & 0xFFFFFFFFFFFFFFFF))
    print()
    print("Expected by the Wasm specification for the IMPLICIT else")
    print("  (the else arm forwards the block parameter):")
    print("    cond=0 (false arm taken) -> value == PV      = %s" % hex(PV))
    print("    cond=1 (true arm taken)  -> value == %s" % hex(THEN_VALUE))


if __name__ == "__main__":
    main()
