#!/usr/bin/env python3
"""
Extracts the JIT-compiled machine code that the production libwasmvm writes to
its cache and analyses the native stack (RSP) balance of every loop.

The cache artifact produced by Wasmer's singlepass backend is the raw code
buffer; this script slices it out, disassembles it and computes, for each
backward jump (loop back-edge), the net RSP movement of the loop body.

Usage:  python3 jit_analyze.py <label> [--param N] [--prefix N] [--explicit]
"""
import glob
import os
import re
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                      # noqa: E402
import upstream_regression as U           # noqa: E402


def extract_jit(wasm, outdir):
    base = outdir
    vm = R.VM()
    cache = vm.init_cache(base)
    checksum = vm.store_code(cache, wasm, checked=True)
    mods = glob.glob(base + "/cache/modules/*/*/%s.module" % checksum.hex())
    if not mods:
        raise RuntimeError("no compiled module in cache")
    data = open(mods[0], "rb").read()
    magiclen = struct.unpack_from("<I", data, 24)[0]
    codelen = struct.unpack_from("<I", data, 28)[0]
    code = data[32:32 + codelen]
    return code, checksum.hex()


def disasm(code):
    path = tempfile.mktemp(suffix=".bin")
    open(path, "wb").write(code)
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


def rsp_delta(ins, lo, hi):
    """Net bytes the native stack pointer moves (positive = stack grows)."""
    total = 0
    detail = []
    for addr, txt in ins:
        if not (lo <= addr < hi):
            continue
        m = re.match(r"add\s+\$0x([0-9a-f]+),%rsp", txt)
        if m:
            total -= int(m.group(1), 16)
            detail.append((addr, "add $0x%s,%%rsp" % m.group(1)))
            continue
        m = re.match(r"sub\s+\$0x([0-9a-f]+),%rsp", txt)
        if m:
            total += int(m.group(1), 16)
            detail.append((addr, "sub $0x%s,%%rsp" % m.group(1)))
            continue
        m = re.match(r"(push|pop)\s+%(\w+)", txt)
        if m:
            total += 8 if m.group(1) == "push" else -8
            detail.append((addr, txt))
    return total, detail


def main():
    label = sys.argv[1] if len(sys.argv) > 1 else "case"
    param = 1
    prefix = 31
    explicit = False
    args = sys.argv[2:]
    for i, a in enumerate(args):
        if a == "--param":
            param = int(args[i + 1])
        if a == "--prefix":
            prefix = int(args[i + 1])
        if a == "--explicit":
            explicit = True

    wasm = U.build_upstream(param, prefix, "empty", explicit, 1000, with_probe=True)
    outdir = tempfile.mkdtemp(prefix="jit-")
    code, checksum = extract_jit(wasm, outdir)
    print("== %s  param=%d prefix=%d explicit=%s" % (label, param, prefix, explicit))
    print("   checksum %s  jit bytes %d" % (checksum, len(code)))
    ins = disasm(code)
    loops = []
    for addr, txt in ins:
        m = re.match(r"j\w+\s+0x([0-9a-f]+)", txt)
        if m:
            tgt = int(m.group(1), 16)
            if tgt < addr and tgt > 0:
                loops.append((tgt, addr))
    seen = set()
    for lo, hi in loops:
        if (lo, hi) in seen:
            continue
        seen.add((lo, hi))
        d, detail = rsp_delta(ins, lo, hi)
        print("   loop [0x%x..0x%x)  net RSP per iteration = %+d bytes%s"
              % (lo, hi, d, "   <== STACK DRIFT" if d else ""))
        if d:
            for a, t in detail:
                print("        0x%-6x %s" % (a, t))
    allsp = [t for a, t in ins if "%rsp" in t]
    print("   total rsp instructions in module: %d" % len(allsp))


if __name__ == "__main__":
    main()
