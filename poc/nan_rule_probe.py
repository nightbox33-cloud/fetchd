#!/usr/bin/env python3
"""
Where exactly does the NaN canonicalization get lost?

`nan_canon_probe.py` showed that a function whose *return value* is the NaN
returns the raw hardware NaN with an implicit else and the canonical one with
an explicit else.  `nan_money_probe.py` then showed the opposite for a value
that is consumed *inside* the function.  Both cannot be true, so the rule is
more subtle than "the implicit else skips canonicalization".

This probe isolates it.  Four shapes, each crossing the `if` in a different
way, each compared implicit vs explicit:

  ret_f64    the NaN is the function's return value
  ret_i64    the NaN is reinterpreted to bits inside the function and returned
  sel_i64    ... and compared with `i64.eq` + `select` (no second `if`)
  if_i64     ... and compared with `i64.eq` + a second `if` (a new frame)

Usage:
    python3 nan_rule_probe.py
"""

import os
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                                        # noqa: E402
from wasm_builder import (                                 # noqa: E402
    F64, I32, I64, Module, op_call, op_else, op_end, op_f64_const_bits,
    op_f64_sqrt, op_if, op_i32_const, op_i32_store, op_i64_const,
    op_i64_eq, op_i64_reinterpret_f64, op_local_get, op_local_set, op_nop,
    op_select,
)

RESP_PTR = 16
RESP_DATA = 64
RAW_NAN = 0xFFF8000000000000
RAW_NAN_I64 = RAW_NAN - (1 << 64)


def body(shape, explicit_else, t_f64):
    """The `if` that carries the NaN is always the same; what changes is what
    happens to the NaN *after* it."""
    b = bytearray()
    b += op_f64_const_bits(struct.unpack("<Q", struct.pack("<d", -1.0))[0])
    b += op_f64_sqrt()
    b += op_i32_const(0)                 # false arm
    b += op_if(t_f64)                    # (param f64)(result f64)
    if explicit_else:
        b += op_else()
    b += op_end()
    # stack: [f64]

    if shape == "ret_f64":
        b += op_local_set(0)             # stash the f64 (i64 slot)
        b += op_local_get(0)
        b += op_i64_reinterpret_f64()
    elif shape == "ret_i64":
        b += op_i64_reinterpret_f64()
    elif shape == "sel_i64":
        # price = if bits == RAW { 900 } else { 1000 }  -- no new frame
        b += op_i64_reinterpret_f64()
        b += op_i64_const(RAW_NAN_I64)
        b += op_i64_eq()
        b += op_i32_const(1000)          # val2
        b += op_i32_const(900)           # val1
        b += op_select()
        b += b"\xad"                    # i64.extend_i32_u
    elif shape == "if_i64":
        b += op_i64_reinterpret_f64()
        b += op_i64_const(RAW_NAN_I64)
        b += op_i64_eq()
        b += op_if()                     # a second frame
        b += op_i32_const(900) + op_local_set(1)
        b += op_else()
        b += op_i32_const(1000) + op_local_set(1)
        b += op_end()
        b += op_local_get(1)
        b += b"\xad"                    # i64.extend_i32_u
    else:
        raise ValueError(shape)
    # publish the 64-bit result: stash it, then store at RESP_DATA
    b += op_local_set(2)
    b += op_i32_const(RESP_DATA) + op_local_get(2)
    b += b"\x37\x03\x00"               # i64.store (align=3, offset=0)
    return bytes(b)


def build(shape, explicit_else):
    m = Module()
    t_f64 = m.add_type([F64], [F64])
    m.add_memory(4, export="memory")
    m.add_data(RESP_PTR, RESP_DATA.to_bytes(4, "little") + (8).to_bytes(4, "little")
               + (8).to_bytes(4, "little"))
    m.add_data(RESP_DATA, b"\x00" * 8)
    m.add_data(1024, (2048).to_bytes(4, "little") + (4096).to_bytes(4, "little")
               + (0).to_bytes(4, "little"))

    # 0 = f64 stash, 1 = i32 scratch, 2 = i64 result
    locals_ = [F64, I32, I64]
    fn = m.add_func([], [], locals=locals_,
                    body=body(shape, explicit_else, t_f64))
    m.add_func([I32, I32, I32], [I32],
               body=op_call(fn) + op_i32_const(RESP_PTR), export="execute")
    m.add_func([I32, I32, I32], [I32], body=op_i32_const(RESP_PTR),
               export="instantiate")
    m.add_func([I32], [I32], body=op_i32_const(1024), export="allocate")
    m.add_func([I32], [], body=op_nop(), export="deallocate")
    m.add_func([], [], body=op_nop(), export="interface_version_8")
    return m.build()


def run(wasm):
    vm = R.VM()
    base = tempfile.mkdtemp(prefix="wasmvm-rule-")
    cache = vm.init_cache(base)
    checksum = vm.store_code(cache, wasm, checked=True)
    vm.instantiate(cache, checksum, 1 << 62)
    out, rep, err = vm.execute(cache, checksum, 1 << 62)
    if vm._vec_str(err):
        return None, vm._vec_str(err).strip().splitlines()[-1][:120]
    return int.from_bytes(vm._vec_bytes(out)[:8], "little"), None


def main():
    print("¿Dónde se pierde exactamente la canonicalización?")
    print("libwasmvm: %s" % R.LIB)
    print("=" * 82)
    print("%-10s %-12s %-12s %-12s %s"
          % ("forma", "implicito", "explicito", "esperado", "nota"))
    print("-" * 82)
    for shape, note in (("ret_f64", "el NaN es el retorno"),
                        ("ret_i64", "bits dentro"),
                        ("sel_i64", "select"),
                        ("if_i64", "segundo if")):
        vals = {}
        for exp in (False, True):
            v, err = run(build(shape, exp))
            if err:
                vals[exp] = "ERROR"
            else:
                vals[exp] = v
        imp, exp_ = vals[False], vals[True]
        fmt = (lambda v: "0x%016x" % v) if isinstance(imp, int) else str(imp)
        fmt2 = (lambda v: "0x%016x" % v) if isinstance(exp_, int) else str(exp_)
        same = "IGUAL" if imp == exp_ else "** DISTINTO **"
        print("%-10s %-12s %-12s %-12s %s"
              % (shape, fmt(imp), fmt2(exp_), "", "%s (%s)" % (same, note)))
    print("-" * 82)
    print("RAW_NAN (x86 real indefinite) = 0x%016x" % RAW_NAN)
    print("CANONICAL                   = 0x7ff8000000000000")


if __name__ == "__main__":
    main()
