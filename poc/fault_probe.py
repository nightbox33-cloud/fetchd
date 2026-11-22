#!/usr/bin/env python3
"""
Diagnostic: capture the raw SIGSEGV that the Singlepass "implicit else" bug
produces, *before* Wasmer's own signal handler converts it into a Wasm trap.

Wasmer installs its SIGSEGV handler when the VM is created; this script
installs its own handler afterwards so that the faulting address and
instruction pointer are visible.  The JIT mapping is dumped from
/proc/self/maps so that RIP can be located inside the compiled module.

Usage:  python3 fault_probe.py [--iters N] [--prefix N] [--explicit]
"""
import argparse
import ctypes
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                      # noqa: E402
import measure_drift as M               # noqa: E402


def maps():
    out = []
    with open("/proc/self/maps") as fh:
        for line in fh:
            parts = line.split()
            rng = parts[0].split("-")
            lo = int(rng[0], 16)
            hi = int(rng[1], 16)
            out.append((lo, hi, parts[-1] if len(parts) > 5 else "[anon]"))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=200000)
    ap.add_argument("--prefix", type=int, default=4)
    ap.add_argument("--explicit", action="store_true")
    args = ap.parse_args()

    wasm = M.build(args.prefix, args.explicit, args.iters, 10)
    base = tempfile.mkdtemp()
    vm = R.VM()
    cache = vm.init_cache(base)
    checksum = vm.store_code(cache, wasm, checked=True)
    vm.instantiate(cache, checksum, 1 << 62)

    # --- take over SIGSEGV from Wasmer -------------------------------
    libc = ctypes.CDLL("libc.so.6", use_errno=True)

    def handler(sig, info, ctx):
        addr = info.contents.si_addr if info else None
        u = ctypes.cast(ctx, ctypes.POINTER(R.UContext)).contents if ctx else None
        rsp = u.uc_mcontext[R.REG_RSP] if u else 0
        rip = u.uc_mcontext[R.REG_RIP] if u else 0
        sys.stderr.write("FAULT si_addr=%s rsp=%s rip=%s\n"
                         % (hex(addr or 0), hex(rsp), hex(rip)))
        for lo, hi, name in maps():
            if lo <= rip < hi:
                sys.stderr.write("  rip in mapping %s-%s (%s) offset=0x%x\n"
                                 % (hex(lo), hex(hi), name, rip - lo))
            if lo <= (addr or 0) < hi:
                sys.stderr.write("  fault addr in mapping %s-%s (%s) offset=0x%x\n"
                                 % (hex(lo), hex(hi), name, (addr or 0) - lo))
        if addr:
            sys.stderr.write("  fault_addr - rsp = %+d bytes\n" % (addr - rsp))
        sys.stderr.flush()
        os._exit(42)

    class SigAction(ctypes.Structure):
        _fields_ = [
            ("handler", ctypes.c_void_p),
            ("mask", ctypes.c_ubyte * 128),
            ("flags", ctypes.c_int),
            ("restorer", ctypes.c_void_p),
        ]

    cb = R.HANDLER(handler)
    global _KEEP
    _KEEP = cb
    act = SigAction()
    act.handler = ctypes.cast(cb, ctypes.c_void_p)
    act.flags = R.SA_SIGINFO
    libc.sigaction.argtypes = [ctypes.c_int, ctypes.POINTER(SigAction), ctypes.c_void_p]
    libc.sigaction.restype = ctypes.c_int
    import signal as _sig
    if libc.sigaction(_sig.SIGSEGV, ctypes.byref(act), None) != 0:
        raise OSError(ctypes.get_errno(), "sigaction failed")

    res2, rep2, err2 = vm.execute(cache, checksum, 1 << 62)
    sys.stderr.write("no fault: err=%r\n" % R.VM._vec_str(err2)[:120])


if __name__ == "__main__":
    main()
