#!/usr/bin/env python3
"""
Does the Singlepass "implicit else" miscompilation defeat NaN canonicalization?

Background
----------
Singlepass enables NaN canonicalization **by default**
(`lib/compiler-singlepass/src/config.rs:102` -> `enable_nan_canonicalization: true`),
unlike Cranelift/LLVM where it is off.  The reason is consensus-critical: the
canonical NaN (`0x7FC0000000000000` for f64, see `machine_x64.rs::canonicalize_nan`)
makes float results bit-identical on every CPU, so that validators agree on
the app hash.

The canonicalization is *deferred*: operations such as `f64.sqrt`, `f64.floor`,
`f64.ceil`, `f64.trunc` and `f64.nearest` push their result with the
`CanonicalizeType::F64` mark but do **not** canonicalize it in place
(`codegen.rs:1962-1988`).  The value is canonicalized later, when it leaves the
function, in `emit_return_values()`.

The upstream fix moves part of that logic:

* the *vulnerable* compiler copies the block inputs to the result slots with a
  plain `emit_relaxed_mov(Size::S64, ...)` (`Operator::If`), i.e. **without**
  canonicalizing, and the implicit-else false path never reaches
  `emit_return_values()`;
* the *fixed* compiler funnels the implicit-else false path through
  `emit_if_block_end()` -> `emit_return_values()`, which **does** canonicalize.

If that is observable, the same contract would return a different f64 bit
pattern depending on whether the compiler emitted an `if` with an implicit or
an explicit `else` -- and, worse, the implicit-else result would carry the
*hardware* NaN payload (x86: 0xFFF8000000000000, ARM: 0x7FF8000000000000)
instead of the canonical one.

This probe builds the two variants of the same program and compares the exact
64-bit patterns that come back.

Usage:
    python3 nan_canon_probe.py
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
    op_f64_sqrt, op_if, op_i32_store, op_i32_add, op_global_get, op_global_set,
    op_local_get, op_local_set,
    op_i32_const, op_i64_const, op_i64_eq, op_i64_reinterpret_f64, op_i64_store,
    op_nop,
)

RESP_PTR = 16
RESP_DATA = 64

CANONICAL_F64 = 0x7FF8000000000000   # wasmer machine_x64.rs::canonicalize_nan
X86_INDEFINITE = 0xFFF8000000000000        # x86 "real indefinite" NaN
ARM_DEFAULT = 0x7FF8000000000000          # AArch64 default NaN
ODD_PAYLOAD = 0x7FF8000000000001          # a NaN with a non-default payload

# the NaN produced by `f64.sqrt(-1.0)` on x86-64 (SSE): the "real indefinite"
X86_SQRT_NEG = 0xFFF8000000000000


def build(explicit_else, cond, producer, branch=False):
    """producer: 'sqrt' (f64.sqrt of -1.0) or 'raw' (a literal NaN).

    With `branch=True` the contract does not return the bits but *branches* on
    them: if the value is the raw hardware NaN it stores 1, otherwise 2.  That
    turns a float-level difference into a different execution path, i.e. into
    a different contract state (and therefore a different app hash).
    """
    m = Module()
    m.add_memory(4, export="memory")
    m.add_data(RESP_PTR, RESP_DATA.to_bytes(4, "little") + (16).to_bytes(4, "little")
               + (16).to_bytes(4, "little"))
    m.add_data(RESP_DATA, b"\x00" * 16)

    t_f64 = m.add_type([F64], [F64])

    b = bytearray()
    if producer == "sqrt":
        b += op_f64_const_bits(struct.unpack("<Q", struct.pack("<d", -1.0))[0])
        b += op_f64_sqrt()
    else:
        b += op_f64_const_bits(ODD_PAYLOAD)
    b += op_i32_const(cond)
    b += op_if(t_f64)
    # the then-arm: the block parameter *is* the block result
    if explicit_else:
        b += op_else()
        # the else-arm gets the same parameter, which is again the result
    b += op_end()
    b += op_i64_reinterpret_f64()
    if branch:
        # branch on the exact bit pattern of the "real indefinite" NaN
        b += op_i64_const(X86_SQRT_NEG - (1 << 64))
        b += op_i64_eq()
        b += op_if()
        b += op_i32_const(1) + op_local_set(1)
        b += op_else()
        b += op_i32_const(2) + op_local_set(1)
        b += op_end()
        b += op_i32_const(RESP_DATA) + op_local_get(1) + op_i32_store()
    else:
        b += op_local_set(0)                       # stash the 64 bits in a local
        b += op_i32_const(RESP_DATA) + op_local_get(0) + op_i64_store()

    fn = m.add_func([], [], locals=[I64, I32], body=bytes(b))
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
    return struct.unpack("<Q", raw[:8])[0], None


def label(bits):
    if bits is None:
        return "-"
    if bits == CANONICAL_F64:
        return "canonico (wasmer)"
    if bits == X86_INDEFINITE:
        return "NaN x86 (real indefinite)"
    if bits == ARM_DEFAULT:
        return "NaN por defecto ARM"
    if (bits >> 52) & 0x7FF == 0x7FF and (bits & ((1 << 51) - 1)):
        return "NaN con payload"
    return "valor normal"


def main():
    print("Canonicalizacion de NaN: `else` implicito vs `else` explicito")
    print("produccion priv_wasmvm_sec v3.0.8-rc.3")
    print("=" * 104)
    print("%-10s %-5s %-22s %-22s %-22s %s"
          % ("productor", "cond", "implicito", "explicito", "canonico", "juicio"))
    print("-" * 104)

    bad = 0
    for producer in ("sqrt", "raw"):
        for cond in (0, 1):
            imp, e1 = run(build(False, cond, producer))
            exp, e2 = run(build(True, cond, producer))
            if e1 or e2:
                print("%-10s %-5d ERROR %s" % (producer, cond, (e1 or e2)[:60]))
                continue
            same = imp == exp
            if not same:
                bad += 1
            print("%-10s %-5d 0x%016x %-6s 0x%016x %-6s 0x%016x %-6s %s"
                  % (producer, cond, imp, label(imp), exp, label(exp),
                     CANONICAL_F64, "canonico",
                     "ok" if same else "*** DIFIERE ***"))
    print()
    print("casos con diferencia implicito/explicito: %d" % bad)

    print()
    print("El mismo efecto convertido en RAMIFICACION (estado diferente del contrato)")
    print("-" * 104)
    print("%-10s %-5s %-12s %-12s %s"
          % ("productor", "cond", "implicito", "explicito", "juicio"))
    bad2 = 0
    for producer in ("sqrt",):
        for cond in (0, 1):
            imp, e1 = run(build(False, cond, producer, branch=True))
            exp, e2 = run(build(True, cond, producer, branch=True))
            if e1 or e2:
                print("%-10s %-5d ERROR %s" % (producer, cond, (e1 or e2)[:60]))
                continue
            same = imp == exp
            if not same:
                bad2 += 1
            print("%-10s %-5d %-12s %-12s %s"
                  % (producer, cond, imp, exp,
                     "ok" if same else "*** RAMIFICACION DIVERGENTE ***"))
    print()
    print("casos con divergencia de ramificacion: %d" % bad2)
    print("(1 = el NaN crudo del hardware; 2 = el NaN canonico)")
    print()
    print("Referencias:")
    print("   NaN canonico (wasmer)   0x%016x   <- machine_x64.rs::canonicalize_nan" % CANONICAL_F64)
    print("   NaN x86 real indefinite  0x%016x" % X86_INDEFINITE)
    print("   NaN por defecto AArch64  0x%016x" % ARM_DEFAULT)
    print()
    print("El `else` IMPLICITO deja pasar el NaN crudo del hardware (depende de la")
    print("CPU); el `else` EXPLICITO lo canonicaliza.  La canonicalizacion existe")
    print("justo para que el resultado sea identico bit a bit en todos los nodos.")


if __name__ == "__main__":
    main()
