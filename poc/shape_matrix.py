#!/usr/bin/env python3
"""
Differential probe over *shapes* of `if` with an implicit else.

The upstream regression test (`implicit_else_reclaims_inputs`) only covers
`param i64` blocks and its "branch" case uses `br 0` with the block parameter
on the stack, so the expected value coincides with the parameter: that case
**cannot distinguish** a correct compilation from a wrong one.

This probe compares, for every shape, the value produced by the *implicit*
else against the value produced by the **semantically equivalent explicit**
else.  Any difference is a miscompilation of the value semantics, not just of
the stack accounting.

Shapes covered
--------------
  passthrough     the block result is the block parameter
  replace         the then-arm replaces the parameter with a constant
  branch          the then-arm branches out carrying a *different* value
                  (the case the upstream test cannot distinguish)
  unreachable     the then-arm traps, so only the false arm is reachable
  nested          an `if` inside the then-arm of another `if`
  mixed           a block with parameters of two different types (i32, i64)
  f32             a block with an f32 parameter

Usage:
    python3 shape_matrix.py
"""

import os
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                                        # noqa: E402
from wasm_builder import (                                 # noqa: E402
    F32, I32, I64, Module, op_br, op_call, op_else, op_end, op_f32_const_bits,
    op_i32_reinterpret_f32,
    op_i32_const, op_i32_eq, op_i32_store, op_i64_const, op_i64_reinterpret_f64,
    op_global_get, op_global_set, op_i32_add, op_i64_store, op_if,
    op_local_get, op_local_set, op_nop, op_unreachable,
)

RESP_PTR = 16
RESP_DATA = 64
NWORDS = 4

# parameter values used by the shapes
PV1 = 0x0123456789ABCDEF
PV2 = 0x1111111111111111
PV3 = 0x2222222222222222
NEW = 0x00000000DEADBEEF


def op_f64_reinterpret_i64():
    return b"\xbf"


# --------------------------------------------------------------------------
# module construction
# --------------------------------------------------------------------------

def build(params, results, then_body, else_body=b"", explicit=False,
         result_locals=1, arg_push=b"", cond=0):
    """`params`/`results` are lists of wasm types; the values are pushed with
    the helpers the caller provides in `then_body`/`else_body`."""
    m = Module()
    m.add_memory(4, export="memory")
    m.add_data(RESP_PTR, RESP_DATA.to_bytes(4, "little") + (16).to_bytes(4, "little")
               + (16).to_bytes(4, "little"))
    m.add_data(RESP_DATA, b"\x00" * (8 * NWORDS))

    t_block = m.add_type(params, results)

    # locals: 0..n-1 = the parameters, then one local per result to unstack them
    locals_ = list(results)
    b = bytearray()
    for i in range(len(params)):
        b += op_local_get(i)
    b += op_i32_const(1 if cond else 0)   # the branch condition
    b += op_if(t_block)
    b += then_body
    if explicit:
        b += op_else()
        b += else_body
    b += op_end()

    # the results are on the stack (last one on top): unstack them into locals
    for k in range(len(results) - 1, -1, -1):
        b += op_local_set(len(params) + k)
    # ... and store them raw, honouring each result's width
    offs = []
    cur = RESP_DATA
    for k, rt in enumerate(results):
        b += op_i32_const(cur) + op_local_get(len(params) + k)
        if rt == F32:
            b += op_i32_reinterpret_f32()
        if rt in (I32, F32):
            b += op_i32_store()
            offs.append((cur, 4))
            cur += 4
        else:
            b += op_i64_store()
            offs.append((cur, 8))
            cur += 8

    fn = m.add_func(params, [], locals=locals_, body=bytes(b))
    m.add_func([I32, I32, I32], [I32],
               body=arg_push + op_call(fn) + op_i32_const(RESP_PTR),
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
    return m.build(), offs


def run(wasm, offs):
    base = tempfile.mkdtemp()
    vm = R.VM()
    cache = vm.init_cache(base)
    checksum = vm.store_code(cache, wasm, checked=True)
    vm.instantiate(cache, checksum, 1 << 62)
    res, rep, err = vm.execute(cache, checksum, 1 << 62)
    errtxt = vm._vec_str(err)
    if errtxt:
        return None, errtxt
    raw = vm._vec_bytes(res)
    if len(raw) < 8:
        return None, "respuesta corta: %r" % raw
    # the response *is* the region contents (the descriptor points at RESP_DATA)
    data = raw
    out = []
    for off, size in offs:
        chunk = data[off - RESP_DATA: off - RESP_DATA + size]
        out.append(int.from_bytes(chunk, "little"))
    return tuple(out), None


# --------------------------------------------------------------------------
# shapes
# --------------------------------------------------------------------------

def shape_passthrough():
    # (param i64)(result i64); the then-arm keeps the parameter
    return dict(params=[I64], results=[I64], push=op_i64_const(PV1), cond=0,
                then_body=b"", else_body=b"", expect=PV1)


def shape_replace():
    # the then-arm replaces the parameter with a constant
    return dict(params=[I64], results=[I64], push=op_i64_const(PV1), cond=0,
                then_body=op_i64_const(NEW) + op_local_set(0),
                else_body=b"", expect=PV1)


def shape_branch():
    # the then-arm branches out carrying a DIFFERENT value: the expected
    # result is that value, NOT the block parameter.  The upstream test uses
    # `br 0` with the parameter on the stack, so it cannot tell the two apart.
    return dict(params=[I64], results=[I64], push=op_i64_const(PV1), cond=1,
                then_body=op_i64_const(NEW) + op_br(0),
                else_body=b"", expect=NEW)


def shape_unreachable():
    # the then-arm traps: only the false arm is reachable
    return dict(params=[I64], results=[I64], push=op_i64_const(PV1), cond=0,
                then_body=op_unreachable(), else_body=b"", expect=PV1)


def shape_nested():
    # an `if` inside the then-arm of another `if`
    inner = op_i32_const(0) + op_if(0x40) + op_end()
    return dict(params=[I64], results=[I64], push=op_i64_const(PV1), cond=0,
                then_body=inner, else_body=b"", expect=PV1)


def shape_mixed():
    # a block with parameters of two different types
    return dict(params=[I32, I64], results=[I32, I64],
                push=op_i32_const(PV2 & 0xFFFFFFFF) + op_i64_const(PV3),
                then_body=b"", else_body=b"", expect=(PV2 & 0xFFFFFFFF, PV3))


def shape_f32():
    # a block with an f32 parameter (the bits travel through the block)
    return dict(params=[F32], results=[F32],
                push=op_f32_const_bits(0x40490FDB), cond=0,
                then_body=b"", else_body=b"", expect=0x40490FDB)


SHAPES = [
    ("passthrough", shape_passthrough),
    ("replace", shape_replace),
    ("branch", shape_branch),
    ("unreachable", shape_unreachable),
    ("nested", shape_nested),
    ("f32", shape_f32),
]


def main():
    print("Formas de `if` con `else` implicito: implicito vs explicito equivalente")
    print("produccion priv_wasmvm_sec v3.0.8-rc.3")
    print("=" * 100)
    print("%-13s %-26s %-26s %-26s %s"
          % ("forma", "implicito", "explicito", "esperado (spec)", "juicio"))
    print("-" * 100)

    bad = 0
    for name, fn in SHAPES:
        spec = fn()
        w_imp, offs = build(spec["params"], spec["results"],
                            spec["then_body"], spec["else_body"], False,
                            arg_push=spec["push"], cond=spec["cond"])
        w_exp, _ = build(spec["params"], spec["results"],
                         spec["then_body"], spec["else_body"], True,
                         arg_push=spec["push"], cond=spec["cond"])
        imp, e1 = run(w_imp, offs)
        exp, e2 = run(w_exp, offs)
        if e1 or e2:
            print("%-13s ERROR %s" % (name, (e1 or e2)[:60]))
            continue
        spec_exp = spec["expect"]
        if not isinstance(spec_exp, tuple):
            spec_exp = (spec_exp,)
        imp_s = " ".join("%016x" % v for v in imp[:len(spec_exp)])
        exp_s = " ".join("%016x" % v for v in exp[:len(spec_exp)])
        want_s = " ".join("%016x" % (v & 0xFFFFFFFFFFFFFFFF) for v in spec_exp)
        ok = (imp == exp) and (imp[:len(spec_exp)] == tuple(
            v & 0xFFFFFFFFFFFFFFFF for v in spec_exp))
        if not ok:
            bad += 1
        print("%-13s %-26s %-26s %-26s %s"
              % (name, imp_s, exp_s, want_s, "ok" if ok else "*** MAL ***"))
    print()
    print("formas con desviacion: %d" % bad)


if __name__ == "__main__":
    main()
