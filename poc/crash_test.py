#!/usr/bin/env python3
"""
Does the miscompilation kill the host process, or does the VM trap cleanly?

In production (fetchd -> wasmvm -> wasmer singlepass) the *only* SIGSEGV
handler is wasmer's.  Its recovery path (lib/vm/src/trap/traphandlers.rs):

    if !self.coro_trap_handler.stack_ptr_in_bounds(sp) {
        return false;                 // <- cannot recover
    }
    ...
    // "If there is no next handler (SIG_IGN or SIG_DFL), then it's time to
    //  crash. ... we set the signal back to its original disposition and
    //  return. This will cause the faulting op to be re-executed which will
    //  crash in the normal way."
    libc::sigaction(signum, previous, ptr::null_mut());

So the difference between "the transaction fails" and "the node process dies"
is decided by whether the stack pointer is still inside the bounds of the
wasm stack at the moment of the fault.

This script runs the trigger with NO extra SIGSEGV handler (exactly like
production) in a child process and reports how the child died:

    exit 0  + "call stack exhausted"   -> the VM trapped cleanly
    killed by SIGSEGV (rc == -11)       -> the node process would DIE

Several trigger shapes are tested, differing in how many bytes of native
stack each loop iteration leaks (one false `if` with a spilled block
parameter leaks 8 bytes).
"""
import os
import subprocess
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

RESP_PTR = 16
RESP_DATA = 64


def build(ifs_per_iter, iterations, with_call, body_pushes=0, probe_args=0,
          host_call=False):
    """`ifs_per_iter` false `if`s per loop iteration.

    `body_pushes` = number of values the *then* branch leaves on the operand
    stack (they are never executed on the false path, but they change the
    size of the `add rsp, N` that the false path skips).
    """
    m = Module()
    m.add_memory(4, export="memory")
    t_pass = m.add_type([I64], [I64])
    m.add_data(RESP_PTR, RESP_DATA.to_bytes(4, "little") + (4).to_bytes(4, "little")
               + (4).to_bytes(4, "little"))
    m.add_data(RESP_DATA, b"\x00" * 4)

    if host_call:
        # a host import: db_read(key_ptr) -> i32
        db_read = m.add_import("env", "db_read", [I32], [I32])
        probe = None
    elif probe_args:
        probe = m.add_func([I64] * probe_args, [], body=op_nop())
    else:
        probe = m.add_func([], [], body=op_nop())

    b = bytearray()
    b += op_i32_const(iterations) + op_local_set(1)
    b += op_loop()
    for _ in range(ifs_per_iter):
        b += op_local_get(0) * 4        # 4 live values -> the param spills
        b += op_local_get(0)            # the block parameter
        b += op_i32_const(0)            # condition: always false
        b += op_if(t_pass)
        b += op_drop() + op_i64_const(42)     # then-branch (never executed)
        for _ in range(body_pushes):
            b += op_i64_const(7)               # extra values in the then arm
        b += op_end()                     # implicit else
        b += op_drop() * 5                # 4 prefix values + the result
    if with_call:
        if host_call:
            b += op_i32_const(2048) + op_call(db_read) + op_drop()
        elif probe_args:
            # arguments that are live in memory force the stack-argument path
            b += op_local_get(0) * probe_args + op_call(probe)
        else:
            b += op_call(probe)          # touches the stack -> traps on guard
    b += op_local_get(1) + op_i32_const(1) + op_i32_sub() + op_local_tee(1) + op_br_if(0)
    b += op_end()                     # end of the loop
    if with_call == "after":
        # the call happens AFTER the loop: the drift is silent until then
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


def child(ifs_per_iter, iterations, with_call, body_pushes, probe_args=0,
          host_call=False):
    wasm = build(ifs_per_iter, iterations, with_call, body_pushes, probe_args,
                 host_call)
    base = tempfile.mkdtemp()
    vm = R.VM()
    try:
        cache = vm.init_cache(base)
        checksum = vm.store_code(cache, wasm, checked=True)
        vm.instantiate(cache, checksum, 1 << 62)
        res, rep, err = vm.execute(cache, checksum, 1 << 62)
        errtxt = vm._vec_str(err)
        if errtxt:
            print("ERR %s" % errtxt.replace("\n", " ")[:160])
        else:
            print("OK sin error")
        sys.stdout.flush()
    except Exception as exc:                            # noqa: BLE001
        print("EXC %s" % str(exc)[:160])
        sys.stdout.flush()


CASES = [
    # (ifs, iters, call, pushes, probe_args, host_call, label)
    (600, 400, True, 0, 0, False, "600 if/iter (paso 4800 B), con llamada"),
    (1024, 300, True, 0, 0, False, "1024 if/iter (paso 8192 B), con llamada"),
    (2048, 200, True, 0, 0, False, "2048 if/iter (paso 16384 B), con llamada"),
    (4096, 150, True, 0, 0, False, "4096 if/iter (paso 32768 B), con llamada"),
    (600, 400, False, 0, 0, False, "600 if/iter, sin llamada"),
    (1024, 300, False, 0, 0, False, "1024 if/iter, sin llamada"),
    (1, 2000, "after", 0, 0, False, "1 if/iter, llamada DESPUES (n=2000)"),
    (1, 20000, "after", 0, 0, False, "1 if/iter, llamada DESPUES (n=20000)"),
    (1, 60000, "after", 0, 0, False, "1 if/iter, llamada DESPUES (n=60000)"),
    (1, 100000, "after", 0, 0, False, "1 if/iter, llamada DESPUES (n=100000)"),
    (1, 131072, "after", 0, 0, False, "1 if/iter, llamada DESPUES (n=131072)"),
    (1, 200000, "after", 0, 0, False, "1 if/iter, llamada DESPUES (n=200000)"),
    (4, 60000, "after", 0, 0, False, "4 if/iter, llamada DESPUES (n=60000)"),
    (16, 60000, "after", 0, 0, False, "16 if/iter, llamada DESPUES (n=60000)"),
    (1, 400000, True, 0, 0, False, "1 if/iter, llamada sin args"),
    (1, 400000, False, 0, 0, False, "1 if/iter, sin llamada"),
    (1, 400000, True, 0, 1, False, "1 if/iter, llamada con 1 arg"),
    (1, 400000, True, 0, 3, False, "1 if/iter, llamada con 3 args"),
    (1, 400000, True, 0, 6, False, "1 if/iter, llamada con 6 args"),
    (1, 400000, True, 0, 8, False, "1 if/iter, llamada con 8 args"),
    (2, 400000, True, 0, 8, False, "2 if/iter, llamada con 8 args"),
    (1, 400000, True, 0, 0, True, "1 if/iter, llamada a host db_read"),
    (4, 400000, True, 0, 0, True, "4 if/iter, llamada a host db_read"),
]


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--child":
        _c = sys.argv[4]
        _call = True if _c == "1" else (False if _c == "0" else _c)
        child(int(sys.argv[2]), int(sys.argv[3]), _call,
              int(sys.argv[5]), int(sys.argv[6]), sys.argv[7] == "1")
        return
    print("Comportamiento del proceso (sin handler extra, igual que produccion)")
    print("=" * 96)
    print("%-36s %-10s %s" % ("forma", "proceso", "detalle"))
    print("-" * 96)
    for ifs, iters, call, pushes, pargs, hcall, label in CASES:
        p = subprocess.run(
            [sys.executable, os.path.abspath(__file__), "--child",
             str(ifs), str(iters),
             ("after" if call == "after" else ("1" if call else "0")),
             str(pushes), str(pargs), "1" if hcall else "0"],
            capture_output=True, text=True, timeout=600,
        )
        out = (p.stdout or "").strip().replace("\n", " ")
        err = (p.stderr or "").strip().replace("\n", " ")[:80]
        if p.returncode < 0:
            import signal as sg
            signame = {-11: "SIGSEGV", -6: "SIGABRT", -4: "SIGILL"}.get(
                p.returncode, str(p.returncode))
            status = "MUERTO"
            detail = "proceso terminado por %s  <-- CRASH DEL NODO" % signame
        elif p.returncode == 0:
            status = "vive"
            detail = out or err
        else:
            status = "vive(rc=%d)" % p.returncode
            detail = (out or err)[:110]
        print("%-36s %-10s %s" % (label, status, detail))


if __name__ == "__main__":
    main()
