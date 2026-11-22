#!/usr/bin/env python3
"""
Decisive experiment: what does the production VM do when the leaking module
runs under a gas limit that a real fetchd transaction can actually have?

fetchd's consensus_params.block.max_gas is 2_000_000 (fetchhub-3/4) and
baseapp's tx selector refuses to include any tx whose gas limit exceeds it,
so 2_000_000 is the hard ceiling for a single transaction.

The leaking module needs 131_024 iterations, which costs ~1.1e9 gas.  Under
the real ceiling the gas meter must abort the execution long before the
Singlepass stack is exhausted.
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                              # noqa: E402
from reachability import build                   # noqa: E402


def run_with_limit(iterations, prefix, gas_limit):
    wasm = build(prefix, False, iterations)
    base = tempfile.mkdtemp()
    vm = R.VM()
    cache = vm.init_cache(base)
    checksum = vm.store_code(cache, wasm, checked=True)
    vm.instantiate(cache, checksum, gas_limit)
    res2, rep2, err2 = vm.execute(cache, checksum, gas_limit)
    err = vm._vec_str(err2)
    return err, rep2.used_internally


def main():
    print("Leaking module (prefix=4, implicit else) under different gas limits")
    print()
    print("%-16s %-14s %-14s %s"
          % ("gas limit", "iterations", "gas used", "outcome"))
    print("-" * 78)
    for gas_limit, iters in ((2_000_000, 400_000),
                              (2_000_000, 10_000),
                              (10_000_000, 400_000),
                              (100_000_000, 400_000),
                              (1_200_000_000, 400_000),
                              (1 << 62, 400_000)):
        err, used = run_with_limit(iters, 4, gas_limit)
        if "call stack exhausted" in err:
            outcome = "STACK EXHAUSTED (miscompilation triggered)"
        elif "out of gas" in err.lower() or "gas" in err.lower() and "limit" in err.lower():
            outcome = "gas limit hit (miscompilation NOT reached)"
        elif err:
            outcome = err[:44]
        else:
            outcome = "completed"
        print("%-16d %-14d %-14d %s"
              % (gas_limit, iters, used, outcome))
        sys.stdout.flush()


if __name__ == "__main__":
    main()
