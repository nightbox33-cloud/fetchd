#!/usr/bin/env python3
"""
Determines what actually decides the Singlepass stack-exhaustion threshold.

Observed facts so far:
  * the fault happens on a dedicated 1 MiB mmap'd stack with a guard page,
    NOT on the OS thread stack (RSP at fault was ~0x7f7f... while the Python
    thread stack was ~0x7ffc...);
  * the same Wasm module fails at 130,976 iterations when executed from the
    *main* thread but succeeds for 400,000 iterations when executed from a
    Python-created thread.

This script runs the identical module under both execution contexts, with the
default DB callback and with the instrumented one, and reports the outcome
plus the memory map of the dedicated stack region.
"""
import ctypes
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                              # noqa: E402
import measure_drift as M                        # noqa: E402

SP = ctypes.CDLL(os.path.join(HERE, "libsp.so"))
SP.sp_probe.restype = ctypes.c_void_p


def maps_regions():
    out = []
    with open("/proc/self/maps") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 2:
                continue
            lo, hi = (int(x, 16) for x in parts[0].split("-"))
            size = hi - lo
            perms = parts[1]
            if size == 1 << 20 or (perms == "---p" and size <= 1 << 20):
                out.append((lo, hi, size, perms, parts[-1] if len(parts) > 5 else ""))
    return out


def run_on_main_thread(wasm, patch_cb=False, gas_limit=1 << 62):
    """Runs the contract on the *calling* (main) thread."""
    base = tempfile.mkdtemp(prefix="wasmvm-main-")
    vm = R.VM()
    cache = vm.init_cache(base)
    checksum = vm.store_code(cache, wasm, checked=True)
    if patch_cb:
        vt = vm._db.vtable
        samples = []

        def read_db(db, gas_meter, gas_used, key, value_out, err_out):
            samples.append(SP.sp_probe())
            value_out[0] = vm._new_vec(False, None, 0)
            return 0
        vt.read_db = R.DbRead(read_db)
        vm._keep.append(vt.read_db)
    res, rep, err = vm.instantiate(cache, checksum, gas_limit)
    if res.is_none:
        return {"stage": "instantiate", "err": vm._vec_str(err)}
    res2, rep2, err2 = vm.execute(cache, checksum, gas_limit)
    out = {"gas": rep2.used_internally}
    if res2.is_none:
        out["err"] = vm._vec_str(err2)
    else:
        out["resp"] = vm._vec_bytes(res2)[:80].decode(errors="replace")
    return out


def main():
    wasm = M.build(4, False, 400000, 1)
    print("module: measure_drift shape (param=1, prefix=4, host probe every iter)")
    print()
    for label, patch in (("default db callback", False), ("instrumented callback", True)):
        r = run_on_main_thread(wasm, patch_cb=patch)
        print("MAIN THREAD  %-22s -> %s" % (label, r))
        r2 = R.run_once(wasm, 1 << 20)
        print("PY THREAD    %-22s -> err=%r gas=%s"
              % (label, (r2.get("execute_err") or "")[:70], r2.get("gas")))
        print()

    print("1 MiB regions / guard pages in this process:")
    for lo, hi, size, perms, name in maps_regions():
        print("  %012x-%012x size=%8d %-5s %s" % (lo, hi, size, perms, name))


if __name__ == "__main__":
    main()
