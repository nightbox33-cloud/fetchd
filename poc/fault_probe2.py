#!/usr/bin/env python3
"""
Capture the raw SIGSEGV produced by the Singlepass "implicit else" bug.

Uses the raw rt_sigaction(2) syscall with SA_ONSTACK + SA_RESTORER so the
handler still runs when the faulting condition is a stack exhaustion, and
prints the faulting address, the instruction pointer and the mapping it
belongs to.

Usage:  python3 fault_probe2.py [--iters N] [--prefix N] [--explicit]
"""
import argparse
import ctypes
import os
import signal
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                      # noqa: E402
import measure_drift as M               # noqa: E402

SA_SIGINFO = 0x00000004
SA_ONSTACK = 0x08000000
SA_RESTORER = 0x04000000
SIGSEGV = 11
RT_SIGACTION = 13
SIGSTKSZ = 1 << 16


class KernelSigaction(ctypes.Structure):
    _fields_ = [
        ("handler", ctypes.c_void_p),
        ("flags", ctypes.c_ulong),
        ("restorer", ctypes.c_void_p),
        ("mask", ctypes.c_ulong),
    ]


class StackT(ctypes.Structure):
    _fields_ = [
        ("ss_sp", ctypes.c_void_p),
        ("ss_flags", ctypes.c_int),
        ("ss_size", ctypes.c_size_t),
    ]


def maps():
    out = []
    with open("/proc/self/maps") as fh:
        for line in fh:
            parts = line.split()
            rng = parts[0].split("-")
            out.append((int(rng[0], 16), int(rng[1], 16),
                        parts[-1] if len(parts) > 5 else "[anon]"))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=300000)
    ap.add_argument("--prefix", type=int, default=4)
    ap.add_argument("--explicit", action="store_true")
    args = ap.parse_args()

    wasm = M.build(args.prefix, args.explicit, args.iters, 1)
    base = tempfile.mkdtemp()
    vm = R.VM()
    cache = vm.init_cache(base)
    checksum = vm.store_code(cache, wasm, checked=True)
    vm.instantiate(cache, checksum, 1 << 62)

    libc = ctypes.CDLL("libc.so.6", use_errno=True)

    # alternate signal stack so the handler can run on stack exhaustion
    alt = ctypes.create_string_buffer(SIGSTKSZ * 4)
    ss = StackT()
    ss.ss_sp = ctypes.cast(alt, ctypes.c_void_p)
    ss.ss_flags = 0
    ss.ss_size = SIGSTKSZ * 4
    if libc.sigaltstack(ctypes.byref(ss), None) != 0:
        sys.stderr.write("sigaltstack failed\n")
        return

    def handler(sig, info, ctx):
        addr = info.contents.si_addr if info else None
        u = ctypes.cast(ctx, ctypes.POINTER(R.UContext)).contents if ctx else None
        rsp = u.uc_mcontext[R.REG_RSP] if u else 0
        rip = u.uc_mcontext[R.REG_RIP] if u else 0
        out = ["FAULT sig=%d si_code=%d si_addr=%s rsp=%s rip=%s"
               % (sig, info.contents.si_code if info else -1,
                  hex(addr or 0), hex(rsp), hex(rip))]
        for lo, hi, name in maps():
            if lo <= rip < hi:
                out.append("  rip  in %s-%s (%s) +0x%x" % (hex(lo), hex(hi), name, rip - lo))
            if lo <= (addr or 0) < hi:
                out.append("  addr in %s-%s (%s) +0x%x" % (hex(lo), hex(hi), name,
                                                          (addr or 0) - lo))
        if addr:
            out.append("  addr - rsp = %+d bytes" % (addr - rsp))
        # dump the mappings around the fault address
        for lo, hi, name in maps():
            if (addr or 0) - 0x40000 <= lo <= (addr or 0) + 0x40000:
                out.append("    map %s-%s %s" % (hex(lo), hex(hi), name))
        with open("/proc/self/maps") as fh:
            for line in fh:
                parts = line.split()
                rng = parts[0].split("-")
                lo, hi = int(rng[0], 16), int(rng[1], 16)
                if lo <= (addr or 0) < hi or lo <= rsp < hi:
                    out.append("    RAW: %s" % line.strip())
        sys.stderr.write("\n".join(out) + "\n")
        sys.stderr.flush()
        os._exit(42)

    cb = R.HANDLER(handler)
    global _KEEP
    _KEEP = cb
    class GlibcSigaction(ctypes.Structure):
        _fields_ = [
            ("handler", ctypes.c_void_p),
            ("mask", ctypes.c_ubyte * 128),
            ("flags", ctypes.c_int),
            ("restorer", ctypes.c_void_p),
        ]

    act = GlibcSigaction()
    act.handler = ctypes.cast(cb, ctypes.c_void_p)
    act.flags = SA_SIGINFO | SA_ONSTACK
    libc.sigaction.argtypes = [ctypes.c_int, ctypes.POINTER(GlibcSigaction),
                               ctypes.c_void_p]
    libc.sigaction.restype = ctypes.c_int
    if libc.sigaction(SIGSEGV, ctypes.byref(act), None) != 0:
        sys.stderr.write("sigaction failed errno=%d\n" % ctypes.get_errno())
        return

    res2, rep2, err2 = vm.execute(cache, checksum, 1 << 62)
    sys.stderr.write("no fault: err=%r\n" % R.VM._vec_str(err2)[:120])


if __name__ == "__main__":
    main()
