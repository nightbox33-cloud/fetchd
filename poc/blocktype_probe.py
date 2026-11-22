#!/usr/bin/env python3
"""
Does the reachable surface of the `implicit else` miscompilation extend
*beyond* `if (param T)(result T)`?

The report (§2.9.4) claims the only reachable shape is `if (param T)(result T)`
because `max_function_results` defaults to 1.  That limit is computed by
`cosmwasm-vm` from the **type section** only:

    packages/vm/src/parsed_wasm.rs:147
        CompositeInnerType::Func(ft) => {
            this.max_func_results = cmp::max(ft.results().len(), this.max_func_results);
        }

So a block whose type is *not* in the type section would escape the limit.
The binary format offers exactly one such possibility: a **block type encoded
inline** (`0x60` followed by the param/result vectors) instead of a type index.

This probe measures, against the production `.so`:

  1. typeindex   -- `if` with a type index pointing at a 2-result func type
                     (declared in the type section).  Expected: rejected by
                     `max_function_results`.
  2. inline      -- `if` with an inline func type (2 params / 2 results).
                     Expected: rejected by the parser, because the binary
                     format has no inline func block type.
  3. single      -- `if (param i32)(result i32)`, the reachable shape, as a
                     control: it must be accepted and behave correctly.

Usage:
    python3 blocktype_probe.py
"""

import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                                        # noqa: E402
from wasm_builder import (                                 # noqa: E402
    I32, I64, Module, op_call, op_end, op_i32_const, op_i32_store,
    op_i64_const, op_i64_store, op_if, op_local_get, op_local_set,
    op_nop, op_drop, op_global_get, op_global_set, op_i32_add,
)

RESP_PTR = 16
RESP_DATA = 64


def inline_blocktype(params, results):
    """A block type encoded *inline*: 0x60 + vec(params) + vec(results).

    0x60 is the byte that introduces a func type in the binary format; as an
    s33 it would be the negative value -0x20.
    """
    return (b"\x60"
            + bytes([len(params)]) + bytes(params)
            + bytes([len(results)]) + bytes(results))


def build(kind):
    """Builds a contract whose `execute` runs one `if` of the chosen shape."""
    m = Module()
    m.add_memory(4, export="memory")
    m.add_data(RESP_PTR, RESP_DATA.to_bytes(4, "little") + (8).to_bytes(4, "little")
               + (8).to_bytes(4, "little"))
    m.add_data(RESP_DATA, b"\x00" * 32)

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

    b = bytearray()

    if kind == "typeindex":
        # a func type with 2 params and 2 results, declared in the type section
        t = m.add_type([I32, I64], [I32, I64])
        b += op_i32_const(7) + op_i64_const(9)      # the block inputs
        b += op_i32_const(0)                         # false condition
        b += op_if(t)
        b += op_end()
        b += op_drop() + op_drop()                   # the 2 block results
    elif kind == "inline":
        b += op_i32_const(7) + op_i64_const(9)
        b += op_i32_const(0)
        b += b"\x04" + inline_blocktype([I32, I64], [I32, I64])
        b += op_end()
        b += op_drop() + op_drop()
    elif kind == "single":
        t = m.add_type([I32], [I32])
        b += op_i32_const(7)
        b += op_i32_const(0)
        b += op_if(t)
        b += op_end()
        b += op_drop()
    else:
        raise ValueError(kind)

    # store a marker so the host can see the function ran to completion
    b += op_i32_const(RESP_DATA) + op_i32_const(0xABCD) + op_i32_store()
    b += op_i32_const(RESP_PTR)

    m.add_func([I32, I32, I32], [I32], body=bytes(b), export="execute")
    m.add_func([I32, I32, I32], [I32], body=op_i32_const(RESP_PTR),
               export="instantiate")
    m.add_func([], [], body=op_nop(), export="interface_version_8")
    return m.build()


def run(wasm):
    base = tempfile.mkdtemp()
    vm = R.VM()
    cache = vm.init_cache(base)
    try:
        checksum = vm.store_code(cache, wasm, checked=True)
    except Exception as exc:                            # noqa: BLE001
        return "REJECTED", str(exc).strip().splitlines()[-1][:160]
    vm.instantiate(cache, checksum, 1 << 62)
    res, rep, err = vm.execute(cache, checksum, 1 << 62)
    errtxt = vm._vec_str(err)
    if errtxt:
        return "ERROR", errtxt.strip().splitlines()[-1][:160]
    raw = vm._vec_bytes(res)
    if len(raw) < 4:
        return "OK", "respuesta corta: %r" % raw
    return "OK", "marker=0x%08x" % int.from_bytes(raw[:4], "little")


def main():
    print("¿La superficie alcanzable del `else` implícito va más allá de "
          "`if (param T)(result T)`?")
    print("libwasmvm: %s" % R.LIB)
    print("=" * 78)
    for kind, label in (
        ("typeindex", "if con indice de tipo (2 params / 2 resultados)"),
        ("inline",    "if con tipo INLINE   (2 params / 2 resultados)"),
        ("single",    "if (param i32)(result i32)   [control]"),
    ):
        status, detail = run(build(kind))
        print("%-11s %-46s %-9s %s" % (kind, label, status, detail))
    print("=" * 78)
    print("Un `if` multi-resultado necesita un type index (el formato binario")
    print("no admite un tipo func inline), y ese type index vive en la seccion")
    print("Type, que es exactamente lo que `max_function_results` cuenta.")


if __name__ == "__main__":
    main()
