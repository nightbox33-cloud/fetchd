#!/usr/bin/env python3
"""
Is the *value* produced by an `if` with an implicit `else` correct?

The audit proved the miscompilation exhausts the native stack.  But the same
defect also corrupts the data flow: upstream v7.4.2 `Operator::If` ends with

    if param_types.len() == return_types.len() {
        for (input, return_value) in self.value_stack.iter().rev()
                .take(param_types.len())
                .zip(self.value_stack.iter().rev().skip(param_types.len()))
        {
            self.machine.emit_relaxed_mov(Size::S64, input.0, return_value.0)?;
        }
    }

which, given the value stack layout produced by
`allocate_return_slots_and_swap(param_types.len() + 1, return_types.len())`,
copies the **condition** (i32) into the **block parameter** slot (i64) with a
64-bit move, instead of forwarding the parameter to the result slot.  The
upstream fix deletes this hunk entirely.

Oracle used here (no reference compiler needed): the same construct written
with an **explicit** `else` that forwards the parameter, which is exactly what
the WebAssembly specification mandates for an implicit else.  Any difference
between the two is a miscalculation the contract cannot observe.

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
    op_loop, op_br_if, op_call, op_i32_store, op_i32_add, op_global_get, op_global_set,
    op_i64_add,
)

RESP_PTR = 16
RESP_DATA = 64
SENT = [0x1111111111111111, 0x2222222222222222,
        0x3333333333333333, 0x4444444444444444]
SENT_SUM = sum(SENT) & 0xFFFFFFFFFFFFFFFF
PV = 0x0123456789ABCDEF
THEN_VALUE = 999


def op_i64_store(offset=0, align=3):
    return b"\x37" + bytes([align]) + bytes([offset])


def build(explicit_else, cond, iterations, prefix, chain, then_value=THEN_VALUE):
    """Returns 16 bytes: [0..8) the value of the last `if`, [8..16) the sum of
    four sentinel locals that live on the native stack."""
    m = Module()
    m.add_memory(4, export="memory")
    t_pass = m.add_type([I64], [I64])
    m.add_data(RESP_PTR, RESP_DATA.to_bytes(4, "little") + (16).to_bytes(4, "little")
               + (16).to_bytes(4, "little"))
    m.add_data(RESP_DATA, b"\x00" * 16)

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
    b += op_drop() + op_i64_const(then_value)      # then-branch
    if explicit_else:
        # the explicit else forwards the parameter, exactly like the implicit
        # else is specified to do
        b += op_else()
        b += op_drop() + op_local_get(0)
    b += op_end()
    # The block result is on TOP of the stack; the prefix values sit below
    # it.  Capture the result first, otherwise the prefix drops would remove
    # the result itself and the probe could never observe a difference
    # between the implicit and the explicit else.
    if chain:
        b += op_local_tee(0) + op_drop()
    else:
        b += op_drop()
    for _ in range(prefix):
        b += op_drop()
    b += op_local_get(2) + op_i32_const(1) + op_i32_sub() + op_local_tee(2) + op_br_if(0)
    b += op_end()

    b += (op_local_get(4) + op_local_get(5) + op_i64_add()
          + op_local_get(6) + op_local_get(7) + op_i64_add() + op_i64_add()
          + op_local_set(3))
    b += op_i32_const(RESP_DATA) + op_local_get(0) + op_i64_store()
    b += op_i32_const(RESP_DATA + 8) + op_local_get(3) + op_i64_store()

    fn = m.add_func([], [], locals=[I64, I32, I32, I64, I64, I64, I64, I64],
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
    if len(raw) < 16:
        return None, "respuesta corta: %r" % raw
    # UNSIGNED: the sentinel sum 0xAAAAAAAAAAAAAAAA has the high bit set and
    # would read back as a negative number with a signed unpack, which made
    # every case look like a deviation.
    val, sent = struct.unpack("<QQ", raw[:16])
    return (val, sent), None


def main():
    print("Valor producido por `if (param i64)(result i64)` con else IMPLÍCITO vs EXPLÍCITO")
    print("producción priv_wasmvm_sec v3.0.8-rc.3   ·   oráculo = else explícito equivalente")
    print("=" * 104)
    print("%-7s %-5s %-6s %-6s %-20s %-20s %-20s %s"
          % ("prefix", "cond", "iters", "cadena", "implícito", "explícito", "esperado", "juicio"))
    print("-" * 104)
    bad = 0
    for prefix in (0, 1, 3, 4, 8, 16):
        for cond in (0, 1):
            for chain in (True, False):
                iters = 3 if cond else 5
                imp, e1 = run(build(False, cond, iters, prefix, chain))
                exp, e2 = run(build(True, cond, iters, prefix, chain))
                if e1 or e2:
                    print("%-7d %-5d %-6d %-6s %-20s %-20s %-20s ERROR %s"
                          % (prefix, cond, iters, chain, "-", "-", "-", (e1 or e2)[:30]))
                    continue
                vi, si = imp
                ve, se = exp
                # What the spec mandates: the implicit else forwards the
                # block parameter.  With chain=False the result is dropped and
                # local 0 keeps its original value, so the reported value is
                # PV in that case; with chain=True the result is stored back.
                if chain:
                    spec = PV if cond == 0 else THEN_VALUE
                else:
                    spec = PV
                ok = (vi == ve) and (si == SENT_SUM) and (se == SENT_SUM)
                if not ok:
                    bad += 1
                print("%-7d %-5d %-6d %-6s %-20s %-20s %-20s %s%s%s"
                      % (prefix, cond, iters, chain, hex(vi), hex(ve), hex(spec),
                         "ok" if ok else "*** MAL ***",
                         "" if si == SENT_SUM else "  [SENTINELS IMPLICITO:%s]" % hex(si),
                         "" if se == SENT_SUM else "  [SENTINELS EXPLICITO:%s]" % hex(se)))
    print()
    print("casos con desviacion: %d" % bad)


if __name__ == "__main__":
    main()
