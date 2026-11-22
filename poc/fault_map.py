#!/usr/bin/env python3
"""
Maps the guard page of the production Wasm stack.

The harness installs its own SIGSEGV handler *before* the VM is created, so
wasmer's trap handler wins and every *recoverable* trap is swallowed by the VM
and reported as a Wasm error.  This script does the opposite: it creates the
VM first and then replaces the SIGSEGV handler, so *every* fault (recoverable
or not) is observed here, with its fault address, RSP and RIP.

That makes it possible to see

  * where the guard page starts (the fault address),
  * how much room is left between the fault address and the stack pointer,
  * and whether the fault happened in JIT code or in host code (RIP).

Usage:
    python3 fault_map.py --host db_read --prefix 4 [--from N] [--to N]
"""

import argparse
import ctypes
import os
import signal
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                                    # noqa: E402
import crash_window as C                              # noqa: E402

HANDLER = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.POINTER(R.SigInfo),
                            ctypes.c_void_p)

STATE = {"hit": False, "addr": None, "rsp": None, "rip": None}


def _handler(sig, info, ctx):
    STATE["hit"] = True
    if info:
        STATE["addr"] = info.contents.si_addr
    if ctx:
        u = ctypes.cast(ctx, ctypes.POINTER(R.UContext)).contents
        STATE["rsp"] = u.uc_mcontext[R.REG_RSP]
        STATE["rip"] = u.uc_mcontext[R.REG_RIP]
    # do not return into the faulting instruction
    os._exit(43)


def install_after_vm():
    libc = ctypes.CDLL("libc.so.6", use_errno=True)

    class SigAction(ctypes.Structure):
        _fields_ = [
            ("handler", ctypes.c_void_p),
            ("mask", ctypes.c_ubyte * 128),
            ("flags", ctypes.c_int),
            ("restorer", ctypes.c_void_p),
        ]

    act = SigAction()
    handler = HANDLER(_handler)
    global _KEEP
    _KEEP = handler
    act.handler = ctypes.cast(handler, ctypes.c_void_p)
    act.flags = R.SA_SIGINFO
    libc.sigaction.argtypes = [ctypes.c_int, ctypes.POINTER(SigAction),
                               ctypes.c_void_p]
    libc.sigaction.restype = ctypes.c_int
    libc.sigaction(signal.SIGSEGV, ctypes.byref(act), None)


def run_with_fault_probe(wasm, stack_size):
    """Runs the module and reports the first fault, if any."""
    STATE.update(hit=False, addr=None, rsp=None, rip=None)
    base = tempfile.mkdtemp(prefix="wasmvm-fm-")
    out = {}

    def target():
        vm = R.VM()                    # the VM installs wasmer's trap handler
        install_after_vm()            # ... and now we take the faults ourselves
        cache = vm.init_cache(base)
        checksum = vm.store_code(cache, wasm, checked=True)
        res, rep, err = vm.instantiate(cache, checksum, 1 << 62)
        if res.is_none:
            out["instantiate_err"] = vm._vec_str(err)
            return
        try:
            res2, rep2, err2 = vm.execute(cache, checksum, 1 << 62)
            out["execute_err"] = vm._vec_str(err2)
        except Exception as exc:
            out["exception"] = repr(exc)

    import threading
    threading.stack_size(stack_size)
    t = threading.Thread(target=target)
    t.start()
    t.join()
    out.update({k: STATE[k] for k in ("hit", "addr", "rsp", "rip")})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="db_read")
    ap.add_argument("--prefix", type=int, default=4)
    ap.add_argument("--from", dest="lo", type=int, default=130978)
    ap.add_argument("--to", dest="hi", type=int, default=130984)
    ap.add_argument("--stack", type=int, default=1 << 20)
    args = ap.parse_args()

    print("host=%s prefix=%d" % (args.host, args.prefix))
    print("%-10s %-8s %-18s %-18s %-18s %s"
          % ("iters", "fault", "fault_addr", "rsp", "rip", "detail"))
    for n in range(args.lo, args.hi + 1):
        # each probe runs in a child: a fault kills the child, not the sweep
        pid = os.fork()
        if pid == 0:
            wasm = C.build_leak_then_host(n, args.host, args.prefix)
            r = run_with_fault_probe(wasm, args.stack)
            err = (r.get("execute_err") or r.get("exception") or "")[:40]
            sys.stdout.write("%-10d %-8s %-18s %-18s %-18s %s\n"
                             % (n, r["hit"], hex(r["addr"] or 0),
                                hex(r["rsp"] or 0), hex(r["rip"] or 0),
                                err.replace("\n", " ")))
            sys.stdout.flush()
            os._exit(0)
        _, status = os.waitpid(pid, 0)
        if status != 0:
            # the child died on the fault (exit code 43)
            sig = status & 0x7F
            code = (status >> 8) & 0xFF
            print("%-10d %-8s %s" % (n, "DIED",
                                     ("exit=%d" % code) if code else ("signal=%d" % sig)))
            sys.stdout.flush()


if __name__ == "__main__":
    main()
