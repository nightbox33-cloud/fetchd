#!/usr/bin/env python3
"""
Exact trigger threshold and gas economics for the Singlepass "implicit else"
stack exhaustion, measured on the production libwasmvm artifact.

Two shapes are measured:
  upstream : the exact upstream regression module (param=1, prefix=4, probe =
             an empty Wasm function)
  hostcall : the same but the probe calls a host import

For each shape:
  * the first iteration count at which the execution fails is found by binary
    search (the harness now records the error vector unconditionally, so an
    empty response is not mistaken for a success);
  * the loop counter is handed to the host callback so the exact iteration
    at which the fault happens is recorded, not just the callback count;
  * the gas consumed per iteration is derived, which is what decides whether
    the trigger is reachable under the chain's gas limits.
"""
import ctypes
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                              # noqa: E402
from wasm_builder import (                       # noqa: E402
    Module, I32, I64, op_i32_const, op_i64_const, op_nop, op_end, op_if, op_else,
    op_drop, op_call, op_local_get, op_local_set, op_local_tee, op_i32_sub,
    op_i64_ne, op_unreachable, op_i32_eq, op_loop, op_global_get, op_global_set,
    op_br_if, op_i32_store,
)

RESP = b'{"ok":{"messages":[],"attributes":[],"events":[],"data":null}}'


def build(prefix_count, explicit, iterations, hostcall):
    """Upstream-shaped module; when hostcall is set the probe calls db_read."""
    m = Module()
    m.add_memory(2, export="memory")
    db_read = m.add_import("env", "db_read", [I32], [I32])
    t_pass = m.add_type([I64], [I64])

    # region at 16 -> payload at 64 ; key region at 1024
    m.add_data(16, (64).to_bytes(4, "little") + len(RESP).to_bytes(4, "little")
               + len(RESP).to_bytes(4, "little"))
    m.add_data(64, RESP)
    m.add_data(1024, (2048).to_bytes(4, "little") + (4096).to_bytes(4, "little")
               + (0).to_bytes(4, "little"))

    g_val = m.add_global(I64, True, op_i64_const(0))
    g_cnt = m.add_global(I32, True, op_i32_const(0))
    if hostcall:
        # the probe passes the loop counter to the host so the faulting
        # iteration can be identified exactly
        # store order in Wasm is [address, value]
        probe = m.add_func([], [],
                           body=op_i32_const(2048) + op_global_get(g_cnt)
                           + op_i32_store()
                           + op_i32_const(2048) + op_call(db_read) + op_drop())
    else:
        probe = m.add_func([], [], body=op_nop())

    b = bytearray()
    b += op_i32_const(iterations) + op_local_set(3)
    b += op_loop()
    for _ in range(prefix_count + 1):
        b += op_local_get(0)
    b += op_local_get(1)
    b += op_if(t_pass)
    if explicit:
        b += op_else()
    b += op_end()
    b += op_global_set(g_val)
    for _ in range(prefix_count):
        b += op_drop()
    b += op_local_get(3) + op_global_set(g_cnt)
    b += op_call(probe)
    b += op_local_get(3) + op_i32_const(1) + op_i32_sub() + op_local_tee(3) + op_br_if(0)
    b += op_end()
    b += op_global_get(g_val)
    check = m.add_func([I64, I32, I64], [I64], locals=[I32], body=bytes(b))

    m.add_func([I32], [I32], body=op_i32_const(1024), export="allocate")
    m.add_func([I32], [], body=op_nop(), export="deallocate")
    m.add_func([I32, I32, I32], [I32], body=op_i32_const(16), export="instantiate")
    ex = bytearray()
    ex += op_i64_const(123) + op_i32_const(0) + op_i64_const(123)
    ex += op_call(check) + op_local_set(3)
    ex += op_i32_const(64) + op_local_get(3) + b"\x37\x03\x00"
    ex += op_i32_const(16)
    m.add_func([I32, I32, I32], [I32], locals=[I64], body=bytes(ex), export="execute")
    m.add_func([], [], body=op_nop(), export="interface_version_8")
    return m.build()


def run(iterations, prefix, explicit, hostcall):
    """Returns (verdict, gas, last_counter, callbacks)."""
    wasm = build(prefix, explicit, iterations, hostcall)
    base = tempfile.mkdtemp()
    vm = R.VM()
    cache = vm.init_cache(base)
    checksum = vm.store_code(cache, wasm, checked=True)
    state = {"n": 0, "last": None}
    if hostcall:
        vt = vm._db.vtable

        def read_db(db, gas_meter, gas_used, key, value_out, err_out):
            state["n"] += 1
            try:
                # the module stored the loop counter at memory[1024] and passes
                # a pointer to it as the db key
                state["last"] = int.from_bytes(
                    ctypes.string_at(key.ptr, 4), "little")
            except Exception:
                state["last"] = None
            value_out[0] = vm._new_vec(False, None, 0)
            return 0
        vt.read_db = R.DbRead(read_db)
        vm._keep.append(vt.read_db)
    vm.instantiate(cache, checksum, 1 << 62)
    res2, rep2, err2 = vm.execute(cache, checksum, 1 << 62)
    err = vm._vec_str(err2)
    verdict = "STACK-EXH" if "call stack exhausted" in err else ("ERR" if err else "ok")
    return verdict, rep2.used_internally, state["last"], state["n"]


def threshold(prefix, explicit, hostcall, hi=400000):
    v, g, last, n = run(hi, prefix, explicit, hostcall)
    if v == "ok":
        return None, g, last, n
    lo, best = 1, None
    while lo <= hi:
        mid = (lo + hi) // 2
        v, g, last, n = run(mid, prefix, explicit, hostcall)
        if v == "ok":
            lo = mid + 1
        else:
            best = mid
            hi = mid - 1
    v, g, last, n = run(best, prefix, explicit, hostcall)
    return best, g, last, n


def main():
    print("Trigger threshold and gas economics (production .so)")
    print()
    for hostcall in (False, True):
        shape = "hostcall" if hostcall else "upstream(wasm probe)"
        for prefix in (4, 31):
            for explicit in (False, True):
                t, gas, last, n = threshold(prefix, explicit, hostcall)
                tag = "explicit" if explicit else "implicit"
                if t is None:
                    print("%-20s prefix=%-3d %-9s -> never fails (gas at 400k=%s)"
                          % (shape, prefix, tag, gas))
                else:
                    print("%-20s prefix=%-3d %-9s -> first fail at iter=%s "
                          "(gas=%s, last counter seen=%s, callbacks=%s)"
                          % (shape, prefix, tag, t, gas, last, n))
                sys.stdout.flush()

    print()
    print("Gas per iteration (implicit, prefix=4, upstream shape):")
    prev = None
    for iters in (1000, 10000, 50000, 100000, 131000, 131072, 140000, 200000):
        v, gas, last, n = run(iters, 4, False, False)
        per = "-"
        if prev and prev[1] and v == "ok":
            per = "%.0f" % ((gas - prev[1]) / float(iters - prev[0]))
        print("   iters=%-8d %-11s gas=%-16s gas/iter=%s"
              % (iters, v, gas, per))
        sys.stdout.flush()
        prev = (iters, gas)


if __name__ == "__main__":
    main()
