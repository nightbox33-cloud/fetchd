#!/usr/bin/env python3
"""
Matriz de operadores: ¿que constructo de Wasm DEJA ESCAPAR el NaN crudo?

§2.9.5 del informe establece la regla con dos ejemplos (`if` con `else`
implicito y `select`).  Esta matriz la **mide** para todos los constructos
que pueden transportar un `f64` a traves del codigo: `if`, `select`, `br_if`,
`br_table`, `return`, `call`, `call_indirect`, `block`, `loop`, `br`,
`local.get/set`, `global.get/set`, `f64.load/store`, `f64.copysign`,
`f64.max/min` y `f64.reinterpret_i64`.

Por que hace falta.  En el backend Singlepass cada valor `f64` de la pila
lleva una marca `CanonicalizeType`.  La canonicalizacion (bit a bit, al
canonico 0x7FF8000000000000) se aplica **solo** en los puntos que la leen:

  * la salida de la funcion          (`emit_return_values`)
  * `local.set` / `local.tee`        (locales de tipo float)
  * `global.set`
  * `f64.store`
  * `i64.reinterpret_f64`             (solo si la marca sigue pendiente)
  * `select`                         (solo si el operando elegido tiene marca)
  * antes de una llamada             (`call` / `call_indirect`)

Si un constructo **borra** la marca (la deja en `None`), el valor sale sin
canonicalizar y el **payload crudo** escapa.  Eso es un canal adicional para
materializar la divergencia, y cada canal es un disparador de split de
consensus (§2.9.7) si el valor llega al estado.

Diseno de la medicion.  Cada constructo va en una funcion auxiliar
`[] -> [f64]`; el trigger la llama y sondea el resultado.  Asi el "escape" se
mide en el punto en que el valor **sale de la funcion**, que es donde le
importa al atacante y al estado.

Dos sondas, porque "observable" y "llega al estado" no son lo mismo:

  A  OBSERVABLE  `i64.reinterpret_f64` + comparacion con el patron crudo.
                 Responde: ¿un atacante puede distinguir el NaN crudo?
  B  ESTADO      `f64.store` a memoria + `i64.load` de vuelta.
                 Responde: ¿el NaN crudo llega al app hash?  (consenso)

Medido sobre el `.so` de produccion (libwasmvm.x86_64.so de fetchd).

Uso:
    python3 nan_operator_matrix.py
"""

import os
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                                        # noqa: E402
from wasm_builder import (                                 # noqa: E402
    F64, I32, I64, Module, op_block, op_br, op_br_if, op_br_table, op_call,
    op_call_indirect, op_drop, op_else, op_end, op_f64_const_bits, op_f64_copysign,
    op_f64_load, op_f64_max, op_f64_min, op_f64_reinterpret_i64, op_f64_sqrt,
    op_f64_store, op_global_get, op_global_set, op_i32_const, op_i32_store,
    op_if,
    op_i64_const, op_i64_eq, op_i64_load, op_i64_reinterpret_f64, op_i64_store,
    op_local_get,
    op_local_set, op_local_tee, op_loop, op_nop, op_return, op_select,
)

RESP_PTR = 16       # el descriptor Region
RESP_DATA = 64      # la carga util de 4 bytes
SEED_DATA = 128     # donde se siembra el NaN crudo en la memoria
RESP_DATA2 = 256    # donde la sonda B escribe el estado

# el NaN crudo que x86-64 produce para sqrt(-1.0) ("real indefinite")
RAW_NAN = 0xFFF8000000000000
RAW_NAN_I64 = RAW_NAN - (1 << 64)       # como constante i64 con signo

NEG_ONE = struct.unpack("<Q", struct.pack("<d", -1.0))[0]
ONE_BITS = struct.unpack("<Q", struct.pack("<d", 1.0))[0]
NEG_ONE_BITS = struct.unpack("<Q", struct.pack("<d", -1.0))[0]
ZERO_BITS = struct.unpack("<Q", struct.pack("<d", 0.0))[0]


# ----------------------------------------------------------------------
# los constructos bajo prueba
#
# Cada uno devuelve un cuerpo de funcion `[] -> [f64]`: deja exactamente un
# f64 en la pila.  `m` es el modulo (para registrar tablas y auxiliares) y
# `t_param` es el tipo (param f64)(result f64), `t_res` el tipo [] -> [f64].
# ----------------------------------------------------------------------

def _sqrt_neg1():
    """El NaN crudo: sqrt(-1.0).  En x86-64 es 'real indefinite'."""
    return op_f64_const_bits(NEG_ONE) + op_f64_sqrt()


def case_baseline(m, t_param, t_res):
    """Control: el NaN crudo recien creado, sin constructo de por medio."""
    return _sqrt_neg1()


def case_if_implicit(m, t_param, t_res):
    """`if` con `else` IMPLICITO: el caso conocido de §2.9.5."""
    return (_sqrt_neg1()
            + op_i32_const(0)          # condicion falsa
            + op_if(t_param)            # (param f64)(result f64)
            + op_end())                 # sin `else`: el valor cae straight


def case_if_explicit(m, t_param, t_res):
    """`if` con `else` EXPLICITO: el control que canonicaliza."""
    return (_sqrt_neg1()
            + op_i32_const(0)
            + op_if(t_param)
            + op_else()
            + op_end())


def case_if_explicit_body(m, t_param, t_res):
    """`if` con `else` explicito y las dos ramas con contenido."""
    return (_sqrt_neg1()
            + op_i32_const(1)          # condicion verdadera
            + op_if(t_param)
            + op_else()
            + op_end())


def case_select(m, t_param, t_res):
    """`select`: no abre frame, no canonicaliza (§2.9.5)."""
    return (_sqrt_neg1()               # val1
            + _sqrt_neg1()              # val2
            + op_i32_const(1)          # c
            + op_select())


def case_br_if(m, t_param, t_res):
    """`br_if` saliendo de un bloque con resultado f64."""
    return (op_block(t_res)
            + _sqrt_neg1()
            + op_i32_const(1)
            + op_br_if(0)
            + op_end())


def case_br_if_not_taken(m, t_param, t_res):
    """`br_if` NO tomado (la rama cae al final del bloque)."""
    return (op_block(t_res)
            + _sqrt_neg1()
            + op_i32_const(0)
            + op_br_if(0)
            + op_end())


def case_br(m, t_param, t_res):
    """`br` incondicional."""
    return (op_block(t_res)
            + _sqrt_neg1()
            + op_br(0)
            + op_end())


def case_br_table(m, t_param, t_res):
    """`br_table` (varios destinos)."""
    return (op_block(t_res)
            + _sqrt_neg1()
            + op_i32_const(0)
            + op_br_table([0], 0)
            + op_end())


def case_return(m, t_param, t_res):
    """`return` temprano con un f64 como valor de retorno."""
    return _sqrt_neg1() + op_return()


def case_block(m, t_param, t_res):
    """`block` con resultado f64 (entrada y salida de frame)."""
    return op_block(t_res) + _sqrt_neg1() + op_end()


def case_loop(m, t_param, t_res):
    """`loop` con resultado f64."""
    return op_loop(t_res) + _sqrt_neg1() + op_end()


def case_local(m, t_param, t_res):
    """`local.set` + `local.get`: ida y vuelta por un local float."""
    return _sqrt_neg1() + op_local_set(0) + op_local_get(0)


def case_local_tee(m, t_param, t_res):
    """`local.tee`: escribe y deja el valor en la pila."""
    return _sqrt_neg1() + op_local_tee(0)


def case_global(m, t_param, t_res):
    """`global.set` + `global.get`."""
    return _sqrt_neg1() + op_global_set(0) + op_global_get(0)


def case_memory_load(m, t_param, t_res):
    """`f64.load` de un NaN crudo YA presente en la memoria del contrato.

    El load empuja la marca en `None`: lo que hay en el estado sale sin
    canonicalizar.  Este es el canal que hace el escape *persistente*.
    """
    return op_i32_const(SEED_DATA) + op_f64_load()


def case_memory_roundtrip(m, t_param, t_res):
    """Carga cruda de la memoria y `f64.store` de vuelta a otra direccion.

    Comprueba que el NaN crudo **sobrevive en el estado**: si el store
    canonicalizara, el estado dejaria de ser divergente.  El direccion va
    DEBAJO del valor porque `f64.store` consume [i32, f64].
    """
    return (op_i32_const(RESP_DATA2)
            + op_i32_const(SEED_DATA)
            + op_f64_load()
            + op_local_set(0)          # marca None: el local NO canonicaliza
            + op_local_get(0)
            + op_f64_store()            # el estado recibe el patron crudo
            + op_local_get(0))          # y el helper devuelve el valor crudo


def case_load_copysign_neg(m, t_param, t_res):
    """`f64.load` (marca perdida) + `f64.copysign` con signo NEGATIVO.

    `f64.copysign` no canonicaliza: es una operacion de bits.  Con `+1.0` el
    bit de signo se borra y el patron resultante coincide con el canonico por
    casualidad; con `-1.0` el signo se conserva y el payload crudo se ve.
    """
    return (op_i32_const(SEED_DATA)
            + op_f64_load()
            + op_f64_const_bits(NEG_ONE_BITS)
            + op_f64_copysign())


def case_load_copysign(m, t_param, t_res):
    """`f64.load` (marca perdida) seguido de `f64.copysign`.

    `f64.copysign` canonicaliza su operando **solo** si la marca sigue
    pendiente.  Con la marca ya perdida, el patron crudo sobrevive a un
    operador que en otro caso si canonicaliza.
    """
    return (op_i32_const(SEED_DATA)
            + op_f64_load()
            + op_f64_const_bits(ONE_BITS)
            + op_f64_copysign())


def case_load_max(m, t_param, t_res):
    """`f64.load` (marca perdida) seguido de `f64.max`."""
    return (op_i32_const(SEED_DATA)
            + op_f64_load()
            + op_f64_const_bits(ZERO_BITS)
            + op_f64_max())


def case_load_select(m, t_param, t_res):
    """`f64.load` (marca perdida) como operando de `select`.

    `select` canonicaliza el operando elegido **solo** si su marca sigue
    pendiente.  Con la marca perdida, el patron crudo sobrevive.
    """
    return (op_i32_const(SEED_DATA)
            + op_f64_load()             # val1 (f64)
            + op_f64_const_bits(ZERO_BITS)   # val2 (f64)
            + op_i32_const(1)           # c
            + op_select())


def case_copysign_direct(m, t_param, t_res):
    """`f64.copysign` directamente sobre el NaN recien creado."""
    return _sqrt_neg1() + op_f64_const_bits(ONE_BITS) + op_f64_copysign()


def case_copysign_local(m, t_param, t_res):
    """`local.get` (marca perdida) + `f64.copysign`."""
    return (_sqrt_neg1()
            + op_local_set(0)
            + op_local_get(0)
            + op_f64_const_bits(ONE_BITS)
            + op_f64_copysign())


def case_max(m, t_param, t_res):
    """`f64.max` con el NaN como primer operando."""
    return _sqrt_neg1() + op_f64_const_bits(ZERO_BITS) + op_f64_max()


def case_min(m, t_param, t_res):
    """`f64.min` con el NaN como primer operando."""
    return _sqrt_neg1() + op_f64_const_bits(ZERO_BITS) + op_f64_min()


def case_reinterpret(m, t_param, t_res):
    """`f64.reinterpret_i64`: materializa un patron arbitrario."""
    return op_i64_const(RAW_NAN_I64) + op_f64_reinterpret_i64()


def case_call(m, t_param, t_res):
    """`call`: el NaN cruza la frontera de la llamada como argumento.

    El backend canonicaliza los argumentos float ANTES de la llamada
    ("canonicalization state will be lost across function calls"), asi que
    este caso deberia canonicalizar.
    """
    m._id_f64 = m.add_func([F64], [F64], body=op_local_get(0))
    return _sqrt_neg1() + op_call(m._id_f64)


def case_call_indirect(m, t_param, t_res):
    """`call_indirect`: lo mismo, pero a traves de una tabla."""
    helper = m.add_func([F64], [F64], body=op_local_get(0))
    m.add_table(2, maximum=2, export="table")   # CosmWasm exige max en la tabla
    m.add_elem(0, 0, [helper])
    # el indice de tabla va ENCIMA del argumento f64
    return _sqrt_neg1() + op_i32_const(0) + op_call_indirect(t_param, 0)


# ----------------------------------------------------------------------
# sondas
# ----------------------------------------------------------------------

def probe_observe(helper_idx):
    """Sonda A: que bits ve un atacante?

    `i64.reinterpret_f64` canonicaliza **solo** si la marca sigue pendiente;
    si ya se perdio, el atacante ve el patron crudo tal cual.  Se vuelcan los
    64 bits exactos, no un booleano: asi se distingue "canonicalizado" de
    "cambiado de signo" y de otros casos.
    """
    return (op_i32_const(RESP_DATA)       # [addr]
            + op_call(helper_idx)          # [addr, f64]
            + op_i64_reinterpret_f64()      # [addr, i64]
            + op_i64_store())              # []


def probe_state(helper_idx):
    """Sonda B: que bits quedan en el ESTADO?

    `f64.store` canonicaliza **solo** si la marca sigue pendiente.  Se
    escribe el valor en la memoria del contrato y se releen los 64 bits.
    """
    return (op_i32_const(RESP_DATA2)      # [addr]
            + op_call(helper_idx)          # [addr, f64]
            + op_f64_store()                # []
            + op_i32_const(RESP_DATA)       # [addr]
            + op_i32_const(RESP_DATA2)      # [addr, addr2]
            + op_i64_load()                 # [addr, i64]
            + op_i64_store())               # []


# ----------------------------------------------------------------------
# construccion del contrato
# ----------------------------------------------------------------------

CASES = [
    ("baseline (control)", case_baseline),
    ("if (else implicito)", case_if_implicit),
    ("if (else explicito)", case_if_explicit),
    ("if (else explicito, rama activa)", case_if_explicit_body),
    ("select", case_select),
    ("br_if (tomado)", case_br_if),
    ("br_if (no tomado)", case_br_if_not_taken),
    ("br", case_br),
    ("br_table", case_br_table),
    ("return", case_return),
    ("block", case_block),
    ("loop", case_loop),
    ("local.set + local.get", case_local),
    ("local.tee", case_local_tee),
    ("global.set + global.get", case_global),
    ("f64.load (memoria)", case_memory_load),
    ("f64.load + f64.store (estado)", case_memory_roundtrip),
    ("f64.load + f64.copysign (+1.0)", case_load_copysign),
    ("f64.load + f64.copysign (-1.0)", case_load_copysign_neg),
    ("f64.load + f64.max", case_load_max),
    ("f64.load + select", case_load_select),
    ("f64.copysign (directo)", case_copysign_direct),
    ("f64.copysign (via local.get)", case_copysign_local),
    ("f64.max", case_max),
    ("f64.min", case_min),
    ("f64.reinterpret_i64", case_reinterpret),
    ("call", case_call),
    ("call_indirect", case_call_indirect),
]


def build(case_fn, probe):
    m = Module()
    t_param = m.add_type([F64], [F64])     # (param f64)(result f64)
    t_res = m.add_type([], [F64])           # [] -> [f64]

    m.add_memory(4, export="memory")
    m.add_data(RESP_PTR, RESP_DATA.to_bytes(4, "little") + (8).to_bytes(4, "little")
               + (8).to_bytes(4, "little"))
    m.add_data(RESP_DATA, b"\x00" * 8)
    # el NaN crudo, sembrado en la memoria del contrato
    m.add_data(SEED_DATA, struct.pack("<Q", RAW_NAN))
    m.add_data(1024, (2048).to_bytes(4, "little") + (4096).to_bytes(4, "little")
               + (0).to_bytes(4, "little"))

    # un global f64 mutable (para el caso global)
    m.add_global(F64, True, op_f64_const_bits(0))

    # la funcion auxiliar que contiene el constructo:  [] -> [f64]
    helper = m.add_func([], [F64], locals=[F64],
                         body=case_fn(m, t_param, t_res))

    # el trigger: llama a la auxiliar y sondea
    trig = m.add_func([], [], locals=[I32], body=probe(helper))

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


def run(wasm):
    vm = R.VM()
    base = tempfile.mkdtemp(prefix="wasmvm-opmatrix-")
    cache = vm.init_cache(base)
    checksum = vm.store_code(cache, wasm, checked=True)
    vm.instantiate(cache, checksum, 1 << 62)
    out, rep, err = vm.query(cache, checksum, 1 << 62)
    if vm._vec_str(err):
        return None, vm._vec_str(err).strip().splitlines()[-1][:120]
    raw = vm._vec_bytes(out)[:8]
    return int.from_bytes(raw, "little"), None


def main():
    print("Matriz de operadores: ¿que constructo deja escapar el NaN crudo?")
    print("libwasmvm: %s" % R.LIB)
    print("=" * 104)
    print("%-34s %-20s %-20s %s" % ("constructo", "A observable", "B estado", "nota"))
    print("-" * 104)

    leaks = []
    for name, fn in CASES:
        row = {}
        for pname, probe in (("A", probe_observe), ("B", probe_state)):
            try:
                val, err = run(build(fn, probe))
            except Exception as exc:                      # noqa: BLE001
                val, err = None, "%s: %s" % (type(exc).__name__, exc)
            row[pname] = (val, err)
        a, aerr = row["A"]
        b, berr = row["B"]
        if aerr or berr:
            note = (aerr or berr)[:62]
        elif a is None or b is None:
            note = "sin medir"
        else:
            a_raw = (a & 0xFFFFFFFFFFFFFFFF) == RAW_NAN
            b_raw = (b & 0xFFFFFFFFFFFFFFFF) == RAW_NAN
            a_canon = (a & 0xFFFFFFFFFFFFFFFF) == 0x7FF8000000000000
            b_canon = (b & 0xFFFFFFFFFFFFFFFF) == 0x7FF8000000000000
            if a_raw:
                note = "ESCAPA (observable)"
                leaks.append(name)
            elif b_raw:
                note = "ESCAPA (solo al estado)"
                leaks.append(name + " [solo estado]")
            elif a_canon and b_canon:
                note = "canonicaliza"
            else:
                note = "otro patron (0x%016x)" % (a & 0xFFFFFFFFFFFFFFFF)
        print("%-34s %-20s %-20s %s" % (
            name,
            ("0x%016x" % a) if a is not None else "err",
            ("0x%016x" % b) if b is not None else "err",
            note))

    print("-" * 104)
    print("Canales por los que escapa el NaN crudo (%d):" % len(leaks))
    for name in leaks:
        print("   - %s" % name)


if __name__ == "__main__":
    main()
