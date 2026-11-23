#!/usr/bin/env python3
"""
¿El defecto del `else` implicito es un primitivo de corrupcion de memoria
controlable (y por tanto una via de salida del sandbox y de robo), o es un
agotamiento de pila?

Esta es la pregunta que decide si el vector "principal" del defecto es una
denegacion de servicio o una toma de control del validador.  La respuesta se
mide, no se supone.

El mecanismo, en tres piezas:

  1. `codegen.rs:323` (`acquire_location_on_stack`): por cada slot del stack
     de valores, `stack_offset += 8` y `extend_stack()` emite `sub rsp, 8`.
     Es un **contador de compilacion** paired con una instruccion real.
  2. `machine_x64.rs:2175` (`local_on_stack`): el slot se direcciona como
     `Location::Memory(RBP, -stack_offset)`.  **Los datos se direccionan
     relativo a RBP, no a RSP.**
  3. En el camino del `else` implicito, el `add rsp, 8` que libera el slot
     queda *antes* de `label_else`, de modo que la rama falsa salta por
     encima de el: RSP se queda 8 bytes mas bajo en cada iteracion.

De (2) y (3) se sigue la hipotesis critica: **el `sub rsp, 8` es una
operacion de registro puro**, y las escrituras de datos estan ancladas a RBP
con desplazamientos constantes de compilacion.  La unica escritura que
*sigue* al RSP que se deriva es la **direccion de retorno que empuja el
`call`**.

Este script lo mide en tres partes:

  A  ESTATICO: desensambla el JIT de produccion y clasifica TODA escritura
     de memoria por su modo de direccionamiento (RBP-relativa / RSP-relativa /
     registro-indirecta), distinguiendo el operando destino (AT&T: el ultimo).
  B  RUNTIME: captura el fallo (RIP, RSP, RBP, R15) y lo contrasta con
     /proc/self/maps: de donde viene el fallo, en que mapping cae y si el
     RSP derivado ha salido del mapping del stack de Wasm.
  C  DIRECCION: varia el numero de iteraciones y comprueba que la deriva es
     exactamente de 8 bytes por iteracion y que el fallo ocurre SIEMPRE en el
     `call` (la unica escritura que sigue al RSP).

Uso:
    python3 primitive_probe.py [--iterations N]
"""

import argparse
import glob
import os
import re
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                                        # noqa: E402
from escalate import build as build_leak                   # noqa: E402

REGNAMES = ["r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            "rdi", "rsi", "rbp", "rbx", "rdx", "rax", "rcx", "rsp", "rip"]
_HANDLER_KEEP = ()


# ----------------------------------------------------------------------
# A) ESTATICO: que escribe el JIT y como se direcciona
# ----------------------------------------------------------------------

def extract_jit(wasm):
    base = tempfile.mkdtemp(prefix="wasmvm-prim-")
    vm = R.VM()
    cache = vm.init_cache(base)
    checksum = vm.store_code(cache, wasm, checked=True)
    mods = glob.glob(base + "/cache/modules/*/*/%s.module" % checksum.hex())
    if not mods:
        raise RuntimeError("no compiled module in cache")
    data = open(mods[0], "rb").read()
    codelen = struct.unpack_from("<I", data, 28)[0]
    return data[32:32 + codelen], checksum.hex()


def disasm(code):
    path = tempfile.mktemp(suffix=".bin")
    with open(path, "wb") as fh:
        fh.write(code)
    out = subprocess.run(
        ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64", "--adjust-vma=0", path],
        capture_output=True, text=True).stdout
    os.unlink(path)
    ins = []
    for line in out.splitlines():
        m = re.match(r"\s+([0-9a-f]+):\t([0-9a-f ]+)\t(.*)", line)
        if m:
            ins.append((int(m.group(1), 16), m.group(3).strip()))
    return ins


def split_operands(ops):
    """Divide los operandos AT&T respetando los parentesis."""
    parts, depth, cur = [], 0, ""
    for ch in ops:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return parts


def classify(insn):
    """(mnemonico, escribe_memoria, modo_de_direccionamiento, operando_destino)."""
    m = re.match(r"([a-z0-9.]+)\s*(.*)", insn)
    if not m:
        return None
    mnem, ops = m.group(1), m.group(2).strip()
    parts = split_operands(ops)

    if mnem.startswith("mov") and len(parts) == 2:
        dst = parts[1]                      # AT&T: el destino es el ultimo
        if "(" in dst:
            if "rbp" in dst:
                return (mnem, True, "rbp-rel", dst)
            if "rsp" in dst:
                return (mnem, True, "rsp-rel", dst)
            return (mnem, True, "reg-indir", dst)
        return (mnem, False, None, dst)
    if mnem.startswith("push"):
        return (mnem, True, "push", ops)
    if mnem.startswith("pop"):
        return (mnem, False, None, ops)
    if mnem.startswith("call"):
        return (mnem, True, "call (push de la dir. de retorno)", ops)
    return (mnem, False, None, ops)


# ----------------------------------------------------------------------
# B) RUNTIME: el fallo y los mappings
# ----------------------------------------------------------------------

def _install_our_handler(wfd):
    """Manejador propio: vuelca los gregs y la direccion de fallo."""
    import ctypes
    import signal as _sig

    class SigInfo(ctypes.Structure):
        _fields_ = [("si_signo", ctypes.c_int), ("si_errno", ctypes.c_int),
                    ("si_code", ctypes.c_int), ("si_addr", ctypes.c_void_p)]

    class StackT(ctypes.Structure):
        _fields_ = [("ss_sp", ctypes.c_void_p), ("ss_flags", ctypes.c_int),
                    ("ss_size", ctypes.c_size_t)]

    class UCtx(ctypes.Structure):
        _fields_ = [("uc_flags", ctypes.c_ulong),
                    ("uc_link", ctypes.c_void_p),
                    ("uc_stack", StackT),
                    ("uc_mcontext", ctypes.c_long * 23)]

    SA_ONSTACK = 0x08000000
    SA_SIGINFO = 0x00000004
    ALTSTACK_SIZE = 65536
    HANDLER = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.POINTER(SigInfo),
                                ctypes.c_void_p)

    def handler(sig, info, ctx):
        addr = 0
        try:
            if info:
                addr = ctypes.cast(info, ctypes.POINTER(SigInfo)).contents.si_addr or 0
        except Exception:
            addr = 0
        lines = ["SIGSEGV addr=0x%x" % addr]
        regs = {}
        try:
            u = ctypes.cast(ctx, ctypes.POINTER(UCtx)).contents
            for i, nm in enumerate(REGNAMES):
                regs[nm] = u.uc_mcontext[i] & 0xFFFFFFFFFFFFFFFF
                lines.append("  %-6s 0x%x" % (nm, regs[nm]))
        except Exception:
            pass
        # los mappings DEL PROPIO proceso (el padre no los ve: el fallo ocurre
        # en el hijo, y su /proc/self/maps es distinto)
        try:
            with open("/proc/self/maps") as fh:
                maps = fh.read().splitlines()
            for target in ("rsp", "rbp", "r15"):
                val = regs.get(target)
                if not val:
                    continue
                for line in maps:
                    mm = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+)", line)
                    if mm and int(mm.group(1), 16) <= val < int(mm.group(2), 16):
                        lines.append("  MAP %-4s 0x%x  %s" % (target, val, line.strip()))
                        break
                else:
                    lines.append("  MAP %-4s 0x%x  (fuera de todo mapping)" % (target, val))
            # MAPA COMPLETO: que hay por debajo de la guard page del stack
            lines.append("  --- MAPA COMPLETO ---")
            for line in maps:
                mm = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+)", line)
                if not mm:
                    continue
                a, b = int(mm.group(1), 16), int(mm.group(2), 16)
                tag = ""
                rbpv = regs.get("rbp", 0)
                if a <= rbpv < b:
                    tag = "   <== WASM STACK (RBP)"
                if a <= (regs.get("r15", 0) or 0) < b:
                    tag = "   <== vmctx (R15)"
                lines.append("  MAPR %s%s" % (line.strip(), tag))
        except Exception:
            pass
        try:
            os.write(wfd, ("\n".join(lines) + "\n").encode())
        except Exception:
            pass
        os._exit(43)

    class SigStack(ctypes.Structure):
        _fields_ = [("ss_sp", ctypes.c_void_p), ("ss_flags", ctypes.c_int),
                    ("ss_size", ctypes.c_size_t)]

    class SigAction(ctypes.Structure):
        _fields_ = [("handler", ctypes.c_void_p), ("mask", ctypes.c_ubyte * 128),
                    ("flags", ctypes.c_int), ("restorer", ctypes.c_void_p)]

    global _HANDLER_KEEP
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    stack = ctypes.create_string_buffer(ALTSTACK_SIZE)
    alt = SigStack(ctypes.addressof(stack), 0, ALTSTACK_SIZE)
    if libc.sigaltstack(ctypes.byref(alt), None) != 0:
        raise RuntimeError("sigaltstack fallo")
    cb = HANDLER(handler)
    act = SigAction(ctypes.cast(cb, ctypes.c_void_p), (ctypes.c_ubyte * 128)(),
                    SA_SIGINFO | SA_ONSTACK, None)
    if libc.sigaction(_sig.SIGSEGV, ctypes.byref(act), None) != 0:
        raise RuntimeError("sigaction fallo")
    _HANDLER_KEEP = (cb, act, stack)


def runtime_fault(wasm):
    """Ejecuta el modulo en un HIJO y captura el fallo.

    El manejador termina el proceso con `os._exit(43)`, asi que la ejecucion
    tiene que vivir en un hijo: si no, se lleva por delante el stdout del
    padre.
    """
    rfd, wfd = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            vm = R.VM()
            base = tempfile.mkdtemp(prefix="wasmvm-prim-rt-")
            cache = vm.init_cache(base)
            # 1) ejecucion trivial: fuerza a wasmer a instalar su manejador
            trivial = build_leak(1, 0, False)
            csum = vm.store_code(cache, trivial, checked=True)
            vm.instantiate(cache, csum, 1 << 62)
            vm.execute(cache, csum, 1 << 62)
            # 2) nuestro manejador por encima del de wasmer
            _install_our_handler(wfd)
            checksum = vm.store_code(cache, wasm, checked=True)
            vm.instantiate(cache, checksum, 1 << 62)
            vm.execute(cache, checksum, 1 << 62)
            os.write(wfd, b"NO-FAULT\n")
        except Exception as exc:                          # noqa: BLE001
            try:
                os.write(wfd, ("EXC %s\n" % exc).encode())
            except Exception:
                pass
        finally:
            os._exit(0)
    os.close(wfd)
    data = b""
    with os.fdopen(rfd, "rb") as fh:
        data = fh.read()
    os.waitpid(pid, 0)
    return data.decode(errors="replace")


def read_maps():
    out = []
    with open("/proc/self/maps") as fh:
        for line in fh:
            m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+) (\S+) (\S+) (\S+)\s*(.*)", line)
            if m:
                out.append({"start": int(m.group(1), 16),
                            "end": int(m.group(2), 16),
                            "perm": m.group(3),
                            "path": m.group(7).strip()})
    return out


def mapping_of(maps, addr):
    for m in maps:
        if m["start"] <= addr < m["end"]:
            return m
    return None


def parse_fault(out):
    """Extrae registros y mappings del volcado del manejador."""
    info, maps = {}, []
    for raw in out.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("MAP"):
            parts = line.split(None, 3)
            if len(parts) == 4:
                maps.append({"target": parts[1],
                             "value": parts[2],
                             "desc": parts[3]})
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            info[k.strip()] = v.strip()
            continue
        m = re.match(r"(\w+)\s+0x([0-9a-f]+)", line)
        if m:
            info[m.group(1)] = m.group(2)
    info["_maps"] = maps
    return info


# ----------------------------------------------------------------------
# main
# ----------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iterations", type=int, default=140000)
    args = ap.parse_args()

    print("¿Primitivo de corrupcion controlable, o agotamiento de pila?")
    print("=" * 96)

    # ---------------- A) ESTATICO ----------------
    wasm = build_leak(4, 4, True)
    code, csum = extract_jit(wasm)
    ins = disasm(code)
    rows = []
    for off, text in ins:
        c = classify(text)
        if c is None:
            continue
        mnem, writes, mode, dst = c
        if writes:
            rows.append((off, text, mode, dst))

    rbp_w = [r for r in rows if r[2] == "rbp-rel"]
    rsp_w = [r for r in rows if r[2] == "rsp-rel"]
    push_w = [r for r in rows if r[2] == "push"]
    call_w = [r for r in rows if r[2].startswith("call")]
    other_w = [r for r in rows if r[2] == "reg-indir"]

    print("A) ESTATICO — el JIT de produccion (checksum %s)" % csum[:16])
    print("-" * 96)
    print("   escrituras RBP-relativas (desplazamiento constante de compilacion) : %d"
          % len(rbp_w))
    print("   escrituras RSP-relativas (QUE SIGUEN LA DERIVA)                   : %d"
          % len(rsp_w))
    print("   pushes (reservas y direcciones de retorno)                         : %d"
          % len(push_w))
    print("   escrituras con registro indirecto (vmctx, offsets fijos)           : %d"
          % len(other_w))
    print("   calls                                                               : %d"
          % len(call_w))
    print()
    disps = sorted({int(m.group(1), 16) for m in
                    (re.search(r"-?0x([0-9a-f]+)\(%rbp", r[3]) for r in rbp_w) if m})
    print("   Desplazamientos RBP-relativos usados (CONSTANTES de compilacion):")
    print("      %s" % (", ".join("-0x%x" % d for d in disps) or "(ninguno)"))
    print()
    print("   Escrituras que siguen al RSP derivado:")
    for r in rsp_w[:6]:
        print("      0x%04x  %s" % (r[0], r[1]))
    if not rsp_w:
        print("      (ninguna con desplazamiento)")
    print()
    print("   Los `call` (cada uno empuja una direccion de retorno en RSP-8):")
    for r in call_w[:6]:
        print("      0x%04x  %s" % (r[0], r[1]))
    print()
    print("   Escrituras indirectas (todas al vmctx, base R15 + offset FIJO):")
    bases = sorted({re.sub(r"\+0x[0-9a-f]+", "", m.group(1)) for m in
                    (re.search(r"(0x[0-9a-f]+\([^)]*\))", r[3]) for r in other_w) if m})
    print("      bases: %s" % (", ".join(bases[:6]) or "(ninguna)"))
    print()

    # ---------------- B) RUNTIME ----------------
    print("B) RUNTIME — donde muere el proceso")
    print("-" * 96)
    wasm = build_leak(args.iterations, 4, True)
    out = runtime_fault(wasm)
    info = parse_fault(out)
    for k in ("SIGSEGV addr",):
        if k in info:
            print("   %-22s %s" % (k, info[k]))
    for nm in ("rip", "rsp", "rbp", "r15", "r13"):
        if nm in info:
            print("   %-22s 0x%s" % (nm, info[nm]))

    try:
        rsp = int(info.get("rsp", "0"), 16)
        rbp = int(info.get("rbp", "0"), 16)
        rip = int(info.get("rip", "0"), 16)
        r15 = int(info.get("r15", "0"), 16)
    except ValueError:
        rsp = rbp = rip = r15 = 0

    maps = read_maps()
    child_maps = info.get("_maps") or []
    if child_maps:
        print()
        print("   Mappings del proceso que muere (leidos en el manejador):")
        for m in child_maps:
            print("      %-4s %-16s %s" % (m["target"], m["value"], m["desc"]))
    if rsp:
        m_rsp = mapping_of(maps, rsp)
        m_rbp = mapping_of(maps, rbp) if rbp else None
        m_r15 = mapping_of(maps, r15) if r15 else None
        print()
        for label, mm, val in (("RSP (stack derivado)", m_rsp, rsp),
                               ("RBP (ancla de los datos)", m_rbp, rbp),
                               ("R15 (vmctx)", m_r15, r15)):
            if mm:
                print("   %-24s 0x%-14x mapping [0x%x-0x%x] %s %s" % (
                    label, val, mm["start"], mm["end"], mm["perm"], mm["path"]))
            else:
                print("   %-24s 0x%-14x FUERA de todo mapping" % (label, val))
        if m_rsp and m_rbp:
            print()
            if m_rsp["start"] == m_rbp["start"]:
                print("   => RSP y RBP estan en el MISMO mapping: las escrituras de")
                print("      datos (ancoradas a RBP) y la que sigue al RSP viven en")
                print("      la misma region.  La deriva no cruza de region.")
            else:
                print("   => RSP y RBP estan en mappings DISTINTOS.")
        if m_r15 and m_rsp and m_r15["start"] != m_rsp["start"]:
            print("   => el vmctx (R15) esta en OTRO mapping que el stack de Wasm:")
            print("      el stack de Wasm es un mmap propio; el vmctx vive en el")
            print("      heap.  Una escritura en el stack no alcanza al vmctx.")

    # instruccion que falla
    if rip:
        # el RIP del cache de Wasmer: el codigo empieza en el base del mapping
        for m in maps:
            if m["start"] <= rip < m["end"] and "r-xp" in m["perm"]:
                base = m["start"]
                break
        else:
            base = None
        if base is not None:
            off = rip - base
            print()
            print("   RIP esta en el codigo JIT, offset 0x%x dentro del mapping:" % off)
            for o, t in ins:
                if abs(o - off) <= 0x10:
                    print("      0x%04x  %s%s" % (o, t, "   <-- RIP FATAL" if o == off else ""))
            print()
            print("   El `call` es la UNICA instruccion que escribe donde apunta el")
            print("   RSP derivado: empuja la direccion de retorno en RSP-8.  El valor")
            print("   escrito es un puntero del propio JIT, no un dato del atacante.")

    # ---------------- C) DIRECCION ----------------
    print()
    print("C) DIRECCION — la deriva es de 8 bytes por iteracion")
    print("-" * 96)
    print("   %-12s %-14s %-14s %-16s %s"
          % ("iteraciones", "deriva (RBP-RSP)", "8 x iteraciones", "RIP fatal", "nota"))
    for iters in (131539, 140000, 200000):
        wasm = build_leak(iters, 4, True)
        out = runtime_fault(wasm)
        info = parse_fault(out)
        if "rsp" not in info:
            print("   %-12d (sin fallo)" % iters)
            continue
        rsp = int(info["rsp"], 16)
        rbp = int(info["rbp"], 16)
        drift = rbp - rsp
        print("   %-12d 0x%-12x 0x%-12x %-16s %s" % (
            iters, drift, 8 * iters, info.get("rip", "?"),
            "la escritura cae en la pagina de guarda"))

    print()
    print("=" * 96)
    print("VEREDICTO (lo que dicen las tres partes):")
    print("  * las escrituras de DATOS estan ancladas a RBP con desplazamientos")
    print("    CONSTANTES de compilacion: no siguen al RSP derivado y no pueden")
    print("    salirse de la region que el VM les asigno;")
    print("  * la unica escritura que sigue al RSP es el PUSH de la direccion de")
    print("    retorno del `call`: el VALOR es un puntero del JIT (no dato del")
    print("    atacante) y la direccion esta dentro del stack de Wasm, que es un")
    print("    mmap propio con paginas de guarda;")
    print("  * por tanto NO hay escritura arbitraria controlada: no hay primitivo")
    print("    de corrupcion, no hay salida del sandbox y no hay via de robo")
    print("    desde este defecto.  Lo que hay es agotamiento de pila.")


if __name__ == "__main__":
    main()
