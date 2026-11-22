#!/usr/bin/env python3
"""
Signal probe that can observe a stack-overflow fault on an exhausted stack.

Derived from the diagnosis in `fault_probe.py`: that script installs its
SIGSEGV handler *without* `SA_ONSTACK`, so it cannot observe a fault that
happens on an exhausted stack -- the kernel tries to push the signal frame
onto the faulting stack, that push faults too, and the process is killed
before the handler ever runs.

wasmer installs its trap handler with `SA_ONSTACK` and an alternate signal
stack, which is what makes a stack overflow recoverable at all.  This module
does the same:

    sigaltstack(64 KiB)  +  sigaction(SIGSEGV, SA_SIGINFO | SA_ONSTACK)

and writes the fault address, RSP, RIP and the /proc/self/maps line that
contains the RIP to a file descriptor supplied by the caller.
"""

import ctypes
import os
import signal

import run_poc as R

SA_ONSTACK = 0x08000000
ALTSTACK_SIZE = 32768

libc = ctypes.CDLL("libc.so.6", use_errno=True)

HANDLER = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.POINTER(R.SigInfo),
                            ctypes.c_void_p)


class SigAction(ctypes.Structure):
    _fields_ = [
        ("handler", ctypes.c_void_p),
        ("mask", ctypes.c_ubyte * 128),
        ("flags", ctypes.c_int),
        ("restorer", ctypes.c_void_p),
    ]


class SigStack(ctypes.Structure):
    _fields_ = [
        ("ss_sp", ctypes.c_void_p),
        ("ss_flags", ctypes.c_int),
        ("ss_size", ctypes.c_size_t),
    ]


_FD = {"w": None}
_KEEP = []


def _mapping_of(addr):
    """The /proc/self/maps line that contains `addr`."""
    with open("/proc/self/maps", "rb") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) < 2:
                continue
            rng = parts[0].decode()
            lo, _, hi = rng.partition("-")
            if int(lo, 16) <= addr < int(hi, 16):
                return line.decode(errors="replace").strip()
    return None


def _handler(sig, info, ctx):
    addr = 0
    rsp = 0
    rip = 0
    try:
        if info:
            addr = info.contents.si_addr or 0
    except Exception:
        addr = 0
    try:
        if ctx:
            u = ctypes.cast(ctx, ctypes.POINTER(R.UContext)).contents
            rsp = u.uc_mcontext[R.REG_RSP]
            rip = u.uc_mcontext[R.REG_RIP]
    except Exception:
        pass
    try:
        os.write(_FD["w"], b"SIGSEGV addr=0x%x rsp=0x%x rip=0x%x\n"
                 % (addr, rsp, rip))
    except Exception:
        pass
    try:
        mapping = _mapping_of(rip)
        if mapping:
            os.write(_FD["w"], b"  rip-mapping: %s\n" % mapping.encode())
    except Exception:
        pass
    os._exit(43)


def install(wfd):
    """Installs the probe handler; faults are written to `wfd`."""
    _FD["w"] = wfd

    buf = ctypes.create_string_buffer(ALTSTACK_SIZE)
    stack = SigStack()
    stack.ss_sp = ctypes.cast(buf, ctypes.c_void_p)
    stack.ss_flags = 0
    stack.ss_size = ALTSTACK_SIZE
    if libc.sigaltstack(ctypes.byref(stack), None) != 0:
        raise OSError(ctypes.get_errno(), "sigaltstack failed")

    handler = HANDLER(_handler)
    _KEEP.append(handler)
    act = SigAction()
    act.handler = ctypes.cast(handler, ctypes.c_void_p)
    act.flags = R.SA_SIGINFO | SA_ONSTACK
    libc.sigaction.argtypes = [ctypes.c_int, ctypes.POINTER(SigAction),
                               ctypes.c_void_p]
    libc.sigaction.restype = ctypes.c_int
    if libc.sigaction(signal.SIGSEGV, ctypes.byref(act), None) != 0:
        raise OSError(ctypes.get_errno(), "sigaction failed")
