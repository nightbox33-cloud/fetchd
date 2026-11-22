#!/usr/bin/env python3
"""
Matrix sweep of the upstream regression-test variants (wasmerio/wasmer @ e5ca9b938
tests/compilers/issues.rs::implicit_else_reclaims_inputs) executed against the
production libwasmvm artifact.

Every case runs in its own child process because a native fault kills the
process.  Usage:  python3 sweep_bodies.py [stack_size] [iterations]
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

BODIES = ["empty", "replace", "branch", "unreachable", "nested-unreachable"]
PREFIXES = [0, 4, 31, 32]
PARAMS = [1, 2]


def run(spec, stack, gas):
    cmd = [sys.executable, os.path.join(HERE, "run_poc.py"), "case", json.dumps(spec),
           str(stack), str(gas)]
    p = subprocess.run(cmd, capture_output=True, text=True)
    out = {"rc": p.returncode, "out": p.stdout, "err": p.stderr}
    gas_used = ""
    for line in p.stdout.splitlines():
        if line.startswith("gas_used="):
            gas_used = line.split("=", 1)[1]
    out["gas"] = gas_used
    return out


def main():
    stack = int(sys.argv[1]) if len(sys.argv) > 1 else (1 << 20)
    iters = int(sys.argv[2]) if len(sys.argv) > 2 else 100000
    print("stack=%d bytes  iterations=%d" % (stack, iters))
    print("%-6s %-20s %-9s %-8s %-14s %s" % ("param", "body", "prefix", "result", "gas", "detail"))
    crashes = []
    traps = []
    for params in PARAMS:
        for body in BODIES:
            for prefix in PREFIXES:
                for explicit in (False, True):
                    spec = {
                        "name": "p%d/%s/pre%d/%s" % (params, body, prefix,
                                                    "explicit" if explicit else "implicit"),
                        "shape": "upstream",
                        "prefix": prefix,
                        "explicit": explicit,
                        "expected": 42 if (explicit and body == "replace") else 123,
                        "params": params,
                        "iterations": iters,
                        "body_kind": body,
                    }
                    r = run(spec, stack, 1 << 62)
                    detail = ""
                    for line in (r["out"] + r["err"]).splitlines():
                        if "SIGSEGV" in line or "***" in line:
                            detail = line.strip()[:80]
                        elif "err=" in line and not detail:
                            detail = line.strip()[:80]
                    if r["rc"] == 42:
                        res = "SIGSEGV"
                        crashes.append(spec["name"])
                    elif "out of bounds" in (r["out"] + r["err"]):
                        res = "OOB-TRAP"
                        traps.append(spec["name"])
                    elif "unreachable" in (r["out"] + r["err"]):
                        res = "TRAP"
                    else:
                        res = "ok"
                    print("%-6d %-20s %-9d %-8s %-14s %s" % (
                        params, body, prefix, res, r["gas"], detail))
                    sys.stdout.flush()
    print()
    print("SIGSEGV (process crash): %d" % len(crashes))
    for c in crashes:
        print("   ", c)
    print("out-of-bounds traps: %d" % len(traps))
    for t in traps[:20]:
        print("   ", t)


if __name__ == "__main__":
    main()
