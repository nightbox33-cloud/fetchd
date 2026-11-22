#!/usr/bin/env python3
"""
Path-sensitive analysis of the native stack balance of the *implicit else*
miscompilation in Singlepass, done on the real JIT code that the production
libwasmvm artifact emits.

Mechanism under test
--------------------
For an `if` with an implicit `else`, singlepass emits, at the `End` of the
block:

        <then arm>
        add   $0x8,%rsp          <- releases the block params / temps
        .Lend:                   <- frame.label
        .Lelse:                  <- label_else  (target of the `jz`)

The conditional jump that implements the `if` targets `.Lelse`, which is
*after* the `add rsp`.  The fall-through (then) path executes the `add rsp`;
the taken (else) path does not.  Every execution of the `if` with a false
condition therefore leaves the native stack pointer 8 bytes lower than the
compiler's own model.

This script extracts the JIT bytes from the wasmer cache, disassembles them and
reports, for every conditional jump *inside a function body*, the stack-pointer
bytes that the taken path skips relative to the fall-through path.

Usage:
    python3 path_balance.py [--param N] [--prefix N] [--explicit]
"""

import argparse
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import jit_analyze as J            # noqa: E402
import upstream_regression as U     # noqa: E402


def cond_jumps(ins):
    """[(addr, mnemonic, target)] for conditional (non-unconditional) jumps."""
    out = []
    for addr, txt in ins:
        m = re.match(r"(j\w+)\s+(0x[0-9a-f]+)", txt)
        if m and not m.group(1).startswith("jmp"):
            out.append((addr, m.group(1), int(m.group(2), 16)))
    return out


def rsp_ops(ins):
    """[(addr, delta, text)]; delta>0 means 'the stack grows' (sub rsp)."""
    ops = []
    for addr, txt in ins:
        m = re.match(r"sub\s+\$0x([0-9a-f]+),%rsp", txt)
        if m:
            ops.append((addr, +int(m.group(1), 16), txt))
            continue
        m = re.match(r"add\s+\$0x([0-9a-f]+),%rsp", txt)
        if m:
            ops.append((addr, -int(m.group(1), 16), txt))
            continue
        m = re.match(r"(push|pop)\s+%(\w+)", txt)
        if m:
            ops.append((addr, +8 if m.group(1) == "push" else -8, txt))
    return ops


def is_epilogue(ops):
    """The callee-saved restore marks the end of a function body."""
    return any(re.match(r"pop\s+%rb[px]", t) for _, _, t in ops)


def analyse(label, wasm, context=8):
    outdir = tempfile.mkdtemp(prefix="jitpb-")
    code, checksum = J.extract_jit(wasm, outdir)
    ins = J.disasm(code)
    ops = rsp_ops(ins)
    addr_of = {a: i for i, (a, _) in enumerate(ins)}

    print("== %s" % label)
    print("   checksum %s   jit bytes %d   insns %d" % (checksum, len(code), len(ins)))

    leaks = []
    for addr, mnem, tgt in cond_jumps(ins):
        if tgt <= addr:
            continue                      # backward jump: a loop back-edge
        skipped = [o for o in ops if addr < o[0] < tgt]
        if not skipped or is_epilogue(skipped):
            continue                      # function-exit jumps are not leaks
        net = sum(o[1] for o in skipped)
        if net == 0:
            continue
        leaks.append((addr, mnem, tgt, net, skipped))

    if not leaks:
        print("   no in-function branch skips stack movement -> balanced")
        return None

    for addr, mnem, tgt, net, skipped in leaks:
        print("   %-6s @0x%-6x -> 0x%-6x : taken path skips net %+d bytes"
              % (mnem, addr, tgt, net))
        for a, d, t in skipped:
            print("        0x%-6x %-24s (%+d)" % (a, t, d))
        i = addr_of.get(addr)
        if i is not None:
            print("        --- context around the branch ---")
            for a, t in ins[max(0, i - context):i + 1]:
                print("        0x%-6x %s" % (a, t))
            j = addr_of.get(tgt)
            if j is not None:
                print("        --- target of the branch (skipped add rsp lives above) ---")
                for a, t in ins[max(0, j - context):j + 3]:
                    print("        0x%-6x %s" % (a, t))
    return leaks[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--param", type=int, default=1)
    ap.add_argument("--prefix", type=int, default=31)
    ap.add_argument("--explicit", action="store_true")
    ap.add_argument("--iterations", type=int, default=1000)
    args = ap.parse_args()

    print("native stack movement skipped by the *taken* branch")
    print("(fall-through path executes it, taken path does not)\n")

    w_imp = U.build_upstream(args.param, args.prefix, "empty", False,
                              args.iterations, with_probe=True)
    w_exp = U.build_upstream(args.param, args.prefix, "empty", True,
                              args.iterations, with_probe=True)

    a = analyse("implicit else (param=%d prefix=%d)" % (args.param, args.prefix), w_imp)
    print()
    b = analyse("explicit else (param=%d prefix=%d)" % (args.param, args.prefix), w_exp)

    print("\n== verdict")
    if a and b and a[3] != 0 and b[3] == 0:
        print("   implicit else: taken branch leaks %+d bytes per execution" % a[3])
        print("   explicit else: balanced")
    elif a and a[3] != 0:
        print("   implicit else: taken branch leaks %+d bytes per execution" % a[3])
    else:
        print("   no imbalance found (unexpected)")


if __name__ == "__main__":
    main()
