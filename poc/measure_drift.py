#!/usr/bin/env python3
"""
Measures the native stack (RSP) drift produced by the Singlepass "implicit
else" code path, using the production CosmWasm C ABI.

The contract calls the host import `env.db_read` once every N loop
iterations.  The Python callback runs on the very same native stack that the
JIT-compiled Wasm code is using, so the address of the callback's C frame is
a direct probe of RSP.  Comparing the samples yields the per-iteration drift
and, therefore, its direction.

Usage:  python3 measure_drift.py [--iters N] [--prefix N] [--every N]
"""
import argparse
import ctypes
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                      # noqa: E402
from wasm_builder import (               # noqa: E402
    Module, I32, I64, op_i32_const, op_i64_const, op_nop, op_end, op_if, op_else,
    op_drop, op_call, op_local_get, op_local_set, op_local_tee, op_i32_sub,
    op_br_if, op_i32_eq, op_i32_eqz, op_loop, op_global_get, op_global_set, op_i32_ge_u,
    op_i32_rem_u,
)

SP = ctypes.CDLL(os.path.join(HERE, "libsp.so"))
SP.sp_probe.restype = ctypes.c_void_p


def stack_probe():
    """Address of the current native stack frame (approximates RSP)."""
    return SP.sp_probe()


def build(prefix_count, explicit, iterations, every, pages=2):
    m = Module()
    m.add_memory(pages, export="memory")
    db_read = m.add_import("env", "db_read", [I32], [I32])
    t_pass = m.add_type([I64], [I64])

    # key region: {offset=64, capacity=4, length=4} ; key bytes at 64
    m.add_data(16, (64).to_bytes(4, "little") + (4).to_bytes(4, "little")
               + (4).to_bytes(4, "little"))
    m.add_data(64, b"key!")
    m.add_data(1024, (2048).to_bytes(4, "little") + (4096).to_bytes(4, "little")
               + (0).to_bytes(4, "little"))

    g_val = m.add_global(I64, True, op_i64_const(0))
    # probe: a Wasm function that calls the host import, so the stack probe is
    # taken *inside* a Wasm->Wasm call sequence.
    probe = m.add_func([], [], body=op_i32_const(16) + op_call(db_read) + op_drop())

    # check(value i64, condition i32) -> i64
    b = bytearray()
    b += op_i32_const(iterations) + op_local_set(2)
    b += op_loop()
    for _ in range(prefix_count + 1):
        b += op_local_get(0)
    b += op_local_get(1)
    b += op_if(t_pass)
    if explicit:
        b += op_else()                # identity else
    b += op_end()
    b += op_global_set(g_val)
    for _ in range(prefix_count):
        b += op_drop()
    # call db_read every `every` iterations
    b += op_local_get(2) + op_i32_const(every) + op_i32_rem_u() + op_i32_eqz() + op_if()
    b += op_call(probe)
    b += op_end()
    b += op_local_get(2) + op_i32_const(1) + op_i32_sub() + op_local_tee(2) + op_br_if(0)
    b += op_end()
    b += op_global_get(g_val)
    check = m.add_func([I64, I32], [I64], locals=[I32], body=bytes(b))

    m.add_func([I32], [I32], body=op_i32_const(1024), export="allocate")
    m.add_func([I32], [], body=op_nop(), export="deallocate")
    m.add_func([I32, I32, I32], [I32], body=op_i32_const(16), export="instantiate")
    ex = (op_i64_const(123) + op_i32_const(0) + op_call(check) + op_local_set(3)
          + op_i32_const(64) + op_local_get(3) + b"\x37\x03\x00"
          + op_i32_const(16))
    m.add_func([I32, I32, I32], [I32], locals=[I64], body=ex, export="execute")
    m.add_func([], [], body=op_nop(), export="interface_version_8")
    return m.build()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=200)
    ap.add_argument("--prefix", type=int, default=31)
    ap.add_argument("--every", type=int, default=10)
    args = ap.parse_args()

    for explicit in (False, True):
        samples = []
        wasm = build(args.prefix, explicit, args.iters, args.every)
        base = tempfile.mkdtemp()
        vm = R.VM()
        cache = vm.init_cache(base)
        checksum = vm.store_code(cache, wasm, checked=True)
        # patch the db callback so it samples the native stack on every call
        vt = vm._db.vtable

        def read_db(db, gas_meter, gas_used, key, value_out, err_out):
            samples.append(stack_probe())
            value_out[0] = vm._new_vec(False, None, 0)
            return 0
        vt.read_db = R.DbRead(read_db)
        vm._keep.append(vt.read_db)
        res, rep, err = vm.instantiate(cache, checksum, 1 << 62)
        res2, rep2, err2 = vm.execute(cache, checksum, 1 << 62)
        errs = R.VM._vec_str(err2)
        print("explicit=%-5s samples=%d err=%r" % (explicit, len(samples), errs[:60]))
        if len(samples) >= 2:
            deltas = [samples[i + 1] - samples[i] for i in range(len(samples) - 1)]
            span = deltas[0] if deltas else 0
            per_iter = span / float(args.every)
            print("   stack samples: first=0x%x last=0x%x" % (samples[0], samples[-1]))
            print("   delta per %d iterations = %+d bytes  ->  %+d bytes/iteration"
                  % (args.every, span, per_iter))
            print("   direction: %s" % ("STACK GROWS (RSP decreasing)" if per_iter < 0
                                        else "STACK SHRINKS (RSP increasing)"))
            print("   all deltas: %s" % sorted(set(deltas)))
            print("   first 12 samples: %s" % [hex(x) for x in samples[:12]])


if __name__ == "__main__":
    main()
