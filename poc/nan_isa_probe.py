#!/usr/bin/env python3
"""
¿Produce la MISMA arquitectura el mismo patron de bits para la MISMA operacion?

La divergencia cross-arquitectura que §2.9.7 da por sentada necesita una
prueba: que x86-64 y AArch64 produzcan **bits distintos** para la misma
operacion de punto flotante invalida.  Este PoC mide las dos ISA.

El lado x86-64 se mide de forma nativa (SSE2 sobre la propia CPU).  El lado
AArch64 se mide con un emulador ARM64 real (Unicorn), ejecutando las
*instrucciones exactas* que el backend Singlepass de ARM64 emite:

    machine_arm64.rs:2229  canonicalize_nan()
        set_default_nan()      -> guarda FPCR y pone DN=1 (Default NaN)
        emit_fmax(input,input) -> FMAX(x,x): con DN=1 devuelve el NaN por
                                   defecto, 0x7FF8000000000000
        restore_fpcr()

Lo que se mide:

  1. FSQRT(-1.0)        operacion invalida.  x86: SQRTSD -> "real indefinite"
                         0xFFF8000000000000.  ARM: FSQRT -> NaN por defecto
                         0x7FF8000000000000.
  2. FMAX(x,x) con DN=1  la canonicalizacion de Singlepass en ARM.
  3. FMAX(x,x) con DN=0  el mismo caso sin la ventana de canonicalizacion.

Si (1) difiere entre arquitecturas, la conclusion es inevitable: el patron
crudo que escapa por el bug del `else` implicito **depende de la CPU**, y un
mismo contrato devuelve valores distintos en un nodo x86-64 y en uno AArch64.

Uso:
    python3 nan_isa_probe.py            (necesita `pip install unicorn`)
"""

import ctypes
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

# ----------------------------------------------------------------------
# AArch64: las instrucciones que el backend de ARM64 emite
# ----------------------------------------------------------------------
MSR_FPCR_X1 = 0xD51B4421      # MSR FPCR, X1   (X1 = el FPCR deseado)
MRS_FPCR_X2 = 0xD53B4422      # MRS X2, FPCR   (para verificar que se fijó)
FMOV_X0_D0 = 0x9E660000       # FMOV X0, D0   (FP -> GP)
FMOV_D0_X0 = 0x9E670000       # FMOV D0, X0   (GP -> FP)
FSQRT_D0_D0 = 0x1E61C000      # FSQRT D0, D0
FMAX_D0_D0_D0 = 0x1E202000    # FMAX  D0, D0, D0   (FMMAX escalar)
FMIN_D0_D0_D0 = 0x1E202800    # FMIN  D0, D0, D0   (FNMMAX escalar)
NOP = 0xD503201F

FPCR_DN = 1 << 25             # bit 25: Default NaN mode

RAW_X86 = 0xFFF8000000000000   # "real indefinite" de SQRTSD(-1.0)
CANON = 0x7FF8000000000000    # el NaN canonico
SNA = 0x7FF0000000000001      # signaling NaN
QNA_OTHER = 0x7FF8000000000001  # quiet NaN con otro payload


def _code(*words):
    return b"".join(struct.pack("<I", w) for w in words)


def arm64_run(insns, x0=0, fpcr=0):
    """Ejecuta una secuencia ARM64 y devuelve (X0, X2, FPCR leido)."""
    try:
        from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
        from unicorn.arm64_const import (
            UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_X0,
            UC_ARM64_REG_X1, UC_ARM64_REG_X2,
        )
    except ImportError:
        return None, "unicorn no instalado (pip install unicorn)"

    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    mu.mem_map(0x1000, 0x2000)
    mu.mem_write(0x1000, insns)
    mu.reg_write(UC_ARM64_REG_SP, 0x8000)
    mu.reg_write(UC_ARM64_REG_X0, x0)
    mu.reg_write(UC_ARM64_REG_X1, fpcr)
    try:
        mu.emu_start(0x1000, 0x1000 + len(insns), count=64)
    except Exception as exc:                      # noqa: BLE001
        return None, "emulacion fallo: %s" % exc
    x0_out = mu.reg_read(UC_ARM64_REG_X0)
    x2_out = mu.reg_read(UC_ARM64_REG_X2)
    return (x0_out, x2_out), None


def arm_probe():
    """Las tres medidas del lado AArch64."""
    out = []

    # --- 1. FSQRT(-1.0) con DN=0 (el valor por defecto de FPCR en Linux) ---
    neg1 = struct.unpack("<Q", struct.pack("<d", -1.0))[0]
    insns = _code(MSR_FPCR_X1, FMOV_D0_X0, FSQRT_D0_D0, FMOV_X0_D0)
    # X1 = 0 -> FPCR = 0 (DN=0)
    res, err = arm64_run(insns, x0=neg1, fpcr=0)
    if err:
        return None, err
    out.append(("FSQRT(-1.0) con FPCR.DN=0", res[0]))

    # --- 2. FSQRT(-1.0) con DN=1 ---
    insns = _code(MSR_FPCR_X1, FMOV_D0_X0, FSQRT_D0_D0, FMOV_X0_D0)
    res, _ = arm64_run(insns, x0=neg1, fpcr=FPCR_DN)
    out.append(("FSQRT(-1.0) con FPCR.DN=1", res[0]))

    # --- 3. FMAX(x,x) con DN=1: la canonicalizacion de Singlepass en ARM ---
    # AVISO: el emulador used here NO implementa la regla "Default NaN" para
    # FMAX (el FPCR se puede escribir, pero la instruccion lo ignora), asi que
    # estas medidas NO verifican la ruta de canonicalizacion de ARM64: son el
    # comportamiento con DN=0.  Se reportan como tales.
    for label, payload in (("crudo x86", RAW_X86), ("canonico", CANON),
                           ("signaling", SNA), ("quiet otro", QNA_OTHER)):
        insns = _code(MSR_FPCR_X1, FMOV_D0_X0, FMAX_D0_D0_D0, FMOV_X0_D0)
        res, _ = arm64_run(insns, x0=payload, fpcr=FPCR_DN)
        out.append(("FMAX(x,x) [DN=1 pedido, no aplicado] sobre %s" % label,
                    res[0]))

    # --- 4. FMAX(x,x) con DN=0: sin la ventana de canonicalizacion ---
    for label, payload in (("crudo x86", RAW_X86), ("signaling", SNA)):
        insns = _code(MSR_FPCR_X1, FMOV_D0_X0, FMAX_D0_D0_D0, FMOV_X0_D0)
        res, _ = arm64_run(insns, x0=payload, fpcr=0)
        out.append(("FMAX(x,x) DN=0 sobre %s" % label, res[0]))

    return out, None


# ----------------------------------------------------------------------
# x86-64: nativo, con SSE2
# ----------------------------------------------------------------------
X86_C = r"""
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <emmintrin.h>
#include <smmintrin.h>

static void show(const char *label, __m128d v) {
    uint64_t bits; memcpy(&bits, &v, 8);
    printf("%s\t0x%016llx\n", label, (unsigned long long)bits);
}

int main(void) {
    double neg1 = -1.0;
    double zero = 0.0;
    uint64_t raw = 0xFFF8000000000000ULL;
    uint64_t sna = 0x7FF0000000000001ULL;
    double d;

    show("SQRTSD(-1.0)", _mm_sqrt_sd(_mm_set_sd(neg1), _mm_set_sd(neg1)));

    memcpy(&d, &raw, 8);
    show("MAXSD(crudo x86, 0.0)", _mm_max_sd(_mm_set_sd(d), _mm_set_sd(zero)));
    show("MINSD(crudo x86, 0.0)", _mm_min_sd(_mm_set_sd(d), _mm_set_sd(zero)));

    memcpy(&d, &sna, 8);
    show("MAXSD(signaling, 0.0)", _mm_max_sd(_mm_set_sd(d), _mm_set_sd(zero)));

    /* la canonicalizacion bit a bit de Singlepass en x86:
       vcmpunordsd + vblendvpd contra 0x7FF8000000000000 */
    uint64_t payload = raw;
    int is_nan = ((payload & 0x7FF0000000000000ULL) == 0x7FF0000000000000ULL)
                 && ((payload & 0x000FFFFFFFFFFFFFULL) != 0);
    printf("canonicalizacion Singlepass x86\t0x%016llx\n",
           (unsigned long long)(is_nan ? 0x7FF8000000000000ULL : payload));
    return 0;
}
"""


def x86_probe():
    tmp = tempfile.mkdtemp(prefix="nanisa-")
    src = os.path.join(tmp, "probe.c")
    exe = os.path.join(tmp, "probe")
    with open(src, "w") as fh:
        fh.write(X86_C)
    cc = subprocess.run(["gcc", "-O0", "-msse4.1", "-o", exe, src],
                         capture_output=True, text=True)
    if cc.returncode != 0:
        return None, "gcc fallo: %s" % cc.stderr.strip()[:200]
    run = subprocess.run([exe], capture_output=True, text=True)
    if run.returncode != 0:
        return None, "el binario fallo: %s" % run.stderr.strip()[:200]
    out = []
    for line in run.stdout.strip().splitlines():
        label, bits = line.split("\t")
        out.append((label, int(bits, 16)))
    return out, None


def main():
    print("Los bits que produce cada ISA para la misma operacion")
    print("=" * 88)
    print("%-42s %s" % ("medida", "bits"))
    print("-" * 88)

    x86, err = x86_probe()
    if err:
        print("x86-64: %s" % err)
    else:
        print("-- x86-64 (nativo, SSE2) " + "-" * 35)
        for label, bits in x86:
            print("%-42s 0x%016x" % (label, bits))

    arm, err = arm_probe()
    if err:
        print("AArch64: %s" % err)
    else:
        print("-- AArch64 (emulacion ARM64 real) " + "-" * 28)
        for label, bits in arm:
            print("%-42s 0x%016x" % (label, bits))

    print("-" * 88)
    if x86 and arm:
        x86map = dict(x86)
        armmap = dict(arm)
        a = x86map.get("SQRTSD(-1.0)")
        b = armmap.get("FSQRT(-1.0) con FPCR.DN=0")
        if a is not None and b is not None:
            if a != b:
                print("DIVERGE: la MISMA operacion invalida produce bits distintos")
                print("   x86-64  SQRTSD(-1.0)  -> 0x%016x" % a)
                print("   AArch64 FSQRT(-1.0)   -> 0x%016x" % b)
                print("   => el patron crudo que escapa por el bug del `else`")
                print("      implicito depende de la CPU: el mismo contrato")
                print("      devuelve valores distintos en nodos distintos.")
            else:
                print("igual: ambas ISA producen 0x%016x" % a)
        print()
        print("LIMITE DE LA MEDICION: el emulador ARM64 usado (Unicorn) no")
        print("implementa la regla \"Default NaN\" (FPCR.DN) para FMAX: el")
        print("FPCR se puede escribir, pero la instruccion lo ignora.  Por tanto")
        print("las medidas de FMAX de arriba son el comportamiento con DN=0, y NO")
        print("verifican la ruta de canonicalizacion de Singlepass en ARM64")
        print("(machine_arm64.rs:2229).  Eso no cambia la conclusion principal:")
        print("el valor de partida (FSQRT(-1.0)) ya difiere entre las dos ISA,")
        print("que es lo que hace divergir el `else` implicito.")


if __name__ == "__main__":
    main()
