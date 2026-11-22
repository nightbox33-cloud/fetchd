#!/usr/bin/env python3
"""
Definitive evidence matrix for the Singlepass "implicit else" miscompilation,
executed against the *production* libwasmvm artifact linked by fetchd
(fetchai/priv_wasmvm_sec v3.0.8-rc.3 -> Wasmer 7.4.2, Singlepass).

Three questions are answered separately:

  1. MATRIX  - the full upstream regression matrix
     (body x param x prefix x condition) reproduced in raw Wasm, run through
     the CosmWasm C ABI of the production .so.
  2. DEPLOYABLE - which of those shapes can actually reach the production
     node.  CosmWasm v3 rejects any module whose *type section* declares a
     function type with more than one result (compatibility.rs,
     check_wasm_functions -> max_func_results), so param=2 is not deployable.
  3. ECONOMICS - gas cost per iteration and the iteration budget needed to
     exhaust the 1 MiB Singlepass stack, compared against the gas limits the
     chain actually imposes.

Usage:
    python3 upstream_matrix.py matrix
    python3 upstream_matrix.py economics
    python3 upstream_matrix.py deployable
"""
import argparse
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                              # noqa: E402
from upstream_regression import build_upstream, BODIES   # noqa: E402


def classify(r):
    """Turns the harness dict into a verdict string."""
    if r.get("store_err"):
        return "REJECTED"
    if r.get("crashed"):
        return "CRASH"
    if r.get("exception"):
        return "ERROR"
    if r.get("instantiate_err"):
        return "INST_ERR"
    err = r.get("execute_err", "")
    if err:
        if "call stack exhausted" in err:
            return "STACK-EXH"
        if "unreachable" in err:
            return "TRAP"
        return "ERR"
    if r.get("resp") is not None:
        return "ok"
    return "?"


def detail(r):
    err = r.get("execute_err") or r.get("instantiate_err") or r.get("store_err") or ""
    return err[:90].replace("\n", " ")


def cmd_matrix(args):
    print("Upstream regression matrix on the production .so")
    print("stack=%d bytes  iterations=%d" % (args.stack, args.iters))
    print()
    print("%-19s %-5s %-6s %-4s %-11s %-14s %s"
          % ("body", "param", "prefix", "cond", "verdict", "gas", "detail"))
    print("-" * 118)
    for body_name, kind, explicit, true_reachable, true_result in BODIES:
        for param_count in (0, 1, 2):
            for prefix_count in (0, 4, 31, 32):
                for condition in (0, 1):
                    if condition == 1 and not true_reachable:
                        continue
                    wasm = build_upstream(param_count, prefix_count, kind,
                                          explicit, args.iters, with_probe=True)
                    r = R.run_once(wasm, args.stack, gas_limit=args.gas_limit)
                    v = classify(r)
                    gas = r.get("gas", "-")
                    print("%-19s %-5d %-6d %-4d %-11s %-14s %s"
                          % (body_name, param_count, prefix_count, condition,
                             v, gas, detail(r)))
                    sys.stdout.flush()


def cmd_deployable(args):
    """Which upstream shapes survive CosmWasm's store-time compatibility check."""
    print("Deployability of each upstream shape (store_code with checked=true)")
    print()
    print("%-19s %-5s %-6s %-13s %s"
          % ("body", "param", "prefix", "verdict", "detail"))
    print("-" * 110)
    for body_name, kind, explicit, _, _ in BODIES:
        for param_count in (0, 1, 2):
            for prefix_count in (0, 4, 31, 32):
                wasm = build_upstream(param_count, prefix_count, kind, explicit,
                                      10, with_probe=True)
                r = R.run_once(wasm, args.stack, gas_limit=args.gas_limit)
                print("%-19s %-5d %-6d %-13s %s"
                      % (body_name, param_count, prefix_count,
                         classify(r), detail(r)))
                sys.stdout.flush()


def cmd_economics(args):
    """Gas per iteration for the deployable leaking shape."""
    print("Gas economics of the leaking shape (param=1, prefix=4, probe)")
    print()
    print("%-12s %-12s %-16s %s" % ("iterations", "verdict", "gas", "gas/iter"))
    print("-" * 66)
    prev = None
    for iters in (1000, 10000, 50000, 100000, 131072, 140000, 200000):
        wasm = build_upstream(1, 4, "empty", False, iters, with_probe=True)
        r = R.run_once(wasm, args.stack, gas_limit=args.gas_limit)
        gas = r.get("gas")
        v = classify(r)
        per = "-"
        if isinstance(gas, int) and prev and prev[1]:
            per = "%.1f" % ((gas - prev[1]) / float(iters - prev[0]))
        print("%-12d %-12s %-16s %s" % (iters, v, gas, per))
        sys.stdout.flush()
        if isinstance(gas, int):
            prev = (iters, gas)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["matrix", "economics", "deployable"])
    ap.add_argument("--stack", type=int, default=1 << 20)
    ap.add_argument("--iters", type=int, default=400000)
    ap.add_argument("--gas-limit", type=int, default=1 << 62)
    args = ap.parse_args()
    {"matrix": cmd_matrix, "economics": cmd_economics,
     "deployable": cmd_deployable}[args.mode](args)


if __name__ == "__main__":
    main()
