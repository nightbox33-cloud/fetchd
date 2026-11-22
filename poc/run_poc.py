#!/usr/bin/env python3
"""
PoC harness: Wasmer singlepass "implicit else" miscompilation in the exact
libwasmvm artifact that fetchd v0.15.1 ships to fetchhub-4
(github.com/fetchai/priv_wasmvm_sec @ d89faf180d3fb5de09b4ba59099844cc0a7a2632,
tag v3.0.8-rc.3 -> internal/api/libwasmvm.x86_64.so, sha256
0b18713c01c57a12d956614c98de6bd247d29b0649e7fa91a53b9444ce80ac32).

The harness talks the real wasmvm C ABI (init_cache / store_code / instantiate /
execute) straight through ctypes, i.e. exactly the code path that wasmd's
MsgStoreCode + MsgExecuteContract use in the fetchd validator.

Nothing here talks to a node: the VM, the compiler (wasmer singlepass 7.4.2) and
the CosmWasm static validation (check_wasm) are the ones inside the shipped
binary.
"""

import ctypes
import json
import os
import shutil
import signal
import sys
import tempfile
import threading

from wasm_builder import build_contract

LIB = os.environ.get(
    "LIBWASMVM",
    "/home/user/fetchd/.audit/priv_wasmvm_sec/internal/api/libwasmvm.x86_64.so",
)

# --------------------------------------------------------------------------
# C ABI types
# --------------------------------------------------------------------------


class ByteSliceView(ctypes.Structure):
    _fields_ = [
        ("is_nil", ctypes.c_bool),
        ("ptr", ctypes.POINTER(ctypes.c_uint8)),
        ("len", ctypes.c_size_t),
    ]


class UnmanagedVector(ctypes.Structure):
    _fields_ = [
        ("is_none", ctypes.c_bool),
        ("ptr", ctypes.POINTER(ctypes.c_uint8)),
        ("len", ctypes.c_size_t),
        ("cap", ctypes.c_size_t),
    ]


class GasReport(ctypes.Structure):
    _fields_ = [
        ("limit", ctypes.c_uint64),
        ("remaining", ctypes.c_uint64),
        ("used_externally", ctypes.c_uint64),
        ("used_internally", ctypes.c_uint64),
    ]


class DbVtable(ctypes.Structure):
    pass


DbRead = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_uint64),
    ByteSliceView,
    ctypes.POINTER(UnmanagedVector),
    ctypes.POINTER(UnmanagedVector),
)
DbWrite = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_uint64),
    ByteSliceView,
    ByteSliceView,
    ctypes.POINTER(UnmanagedVector),
)
DbRemove = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_uint64),
    ByteSliceView,
    ctypes.POINTER(UnmanagedVector),
)
DbScan = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_uint64),
    ByteSliceView,
    ByteSliceView,
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.POINTER(UnmanagedVector),
)

DbVtable._fields_ = [
    ("read_db", DbRead),
    ("write_db", DbWrite),
    ("remove_db", DbRemove),
    ("scan_db", DbScan),
]


class Db(ctypes.Structure):
    _fields_ = [
        ("gas_meter", ctypes.c_void_p),
        ("state", ctypes.c_void_p),
        ("vtable", DbVtable),
    ]


ApiInOut = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ByteSliceView,
    ctypes.POINTER(UnmanagedVector),
    ctypes.POINTER(UnmanagedVector),
    ctypes.POINTER(ctypes.c_uint64),
)
ApiIn = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ByteSliceView,
    ctypes.POINTER(UnmanagedVector),
    ctypes.POINTER(ctypes.c_uint64),
)
QueryFn = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.c_uint64,
    ctypes.POINTER(ctypes.c_uint64),
    ByteSliceView,
    ctypes.POINTER(UnmanagedVector),
    ctypes.POINTER(UnmanagedVector),
)


class GoApiVtable(ctypes.Structure):
    _fields_ = [
        ("humanize_address", ApiInOut),
        ("canonicalize_address", ApiInOut),
        ("validate_address", ApiIn),
    ]


class GoApi(ctypes.Structure):
    _fields_ = [("state", ctypes.c_void_p), ("vtable", GoApiVtable)]


class QuerierVtable(ctypes.Structure):
    _fields_ = [("query_external", QueryFn)]


class GoQuerier(ctypes.Structure):
    _fields_ = [("state", ctypes.c_void_p), ("vtable", QuerierVtable)]


_KEEP_BUFS = []


def view(data: bytes) -> ByteSliceView:
    """ByteSliceView over `data`, keeping the buffer alive for the whole process."""
    if not data:
        return ByteSliceView(False, None, 0)
    buf = ctypes.create_string_buffer(data, len(data))
    _KEEP_BUFS.append(buf)
    return ByteSliceView(False, ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint8)), len(data))


# --------------------------------------------------------------------------
# signal handling (SIGSEGV inside the JIT-ed wasm code)
# --------------------------------------------------------------------------

SA_SIGINFO = 4
SA_RESTORER = 0x04000000
REG_RSP = 15
REG_RIP = 16

CRASH = {"hit": False, "addr": None, "rsp": None, "rip": None, "stack_sp": None, "stack_size": None}


class SigInfo(ctypes.Structure):
    _fields_ = [
        ("si_signo", ctypes.c_int),
        ("si_errno", ctypes.c_int),
        ("si_code", ctypes.c_int),
        ("si_addr", ctypes.c_void_p),
    ]


class StackT(ctypes.Structure):
    _fields_ = [
        ("ss_sp", ctypes.c_void_p),
        ("ss_flags", ctypes.c_int),
        ("ss_size", ctypes.c_size_t),
    ]


class UContext(ctypes.Structure):
    _fields_ = [
        ("uc_flags", ctypes.c_ulong),
        ("uc_link", ctypes.c_void_p),
        ("uc_stack", StackT),
        ("uc_mcontext", ctypes.c_long * 23),
    ]


HANDLER = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.POINTER(SigInfo), ctypes.c_void_p)


def _segv_handler(sig, info, ctx):
    CRASH["hit"] = True
    if info:
        CRASH["addr"] = info.contents.si_addr
    if ctx:
        u = ctypes.cast(ctx, ctypes.POINTER(UContext)).contents
        CRASH["rsp"] = u.uc_mcontext[REG_RSP]
        CRASH["rip"] = u.uc_mcontext[REG_RIP]
        CRASH["stack_sp"] = u.uc_stack.ss_sp
        CRASH["stack_size"] = u.uc_stack.ss_size
    sys.stderr.write(
        "[SIGSEGV] addr=%s rsp=%s rip=%s thread_stack=[%s,+%s)\n"
        % (
            hex(CRASH["addr"] or 0),
            hex(CRASH["rsp"] or 0),
            hex(CRASH["rip"] or 0),
            hex(CRASH["stack_sp"] or 0),
            hex(CRASH["stack_size"] or 0),
        )
    )
    sys.stderr.flush()
    os._exit(42)


def install_segv_handler():
    libc = ctypes.CDLL("libc.so.6", use_errno=True)

    class SigAction(ctypes.Structure):
        _fields_ = [
            ("handler", ctypes.c_void_p),
            ("mask", ctypes.c_ubyte * 128),
            ("flags", ctypes.c_int),
            ("restorer", ctypes.c_void_p),
        ]

    act = SigAction()
    handler = HANDLER(_segv_handler)
    global _KEEP_HANDLER
    _KEEP_HANDLER = handler
    act.handler = ctypes.cast(handler, ctypes.c_void_p)
    act.flags = SA_SIGINFO
    libc.sigaction.argtypes = [ctypes.c_int, ctypes.POINTER(SigAction), ctypes.c_void_p]
    libc.sigaction.restype = ctypes.c_int
    if libc.sigaction(signal.SIGSEGV, ctypes.byref(act), None) != 0:
        raise OSError(ctypes.get_errno(), "sigaction failed")


# --------------------------------------------------------------------------
# wasmvm C API
# --------------------------------------------------------------------------


class VM:
    def __init__(self, lib_path=LIB):
        self.lib = ctypes.CDLL(lib_path, mode=ctypes.RTLD_GLOBAL)
        L = self.lib
        L.init_cache.restype = ctypes.c_void_p
        L.init_cache.argtypes = [ByteSliceView, ctypes.POINTER(UnmanagedVector)]
        L.store_code.restype = UnmanagedVector
        L.store_code.argtypes = [
            ctypes.c_void_p,
            ByteSliceView,
            ctypes.c_bool,
            ctypes.c_bool,
            ctypes.POINTER(UnmanagedVector),
        ]
        L.instantiate.restype = UnmanagedVector
        L.instantiate.argtypes = [
            ctypes.c_void_p, ByteSliceView, ByteSliceView, ByteSliceView, ByteSliceView,
            Db, GoApi, GoQuerier, ctypes.c_uint64, ctypes.c_bool,
            ctypes.POINTER(GasReport), ctypes.POINTER(UnmanagedVector),
        ]
        L.execute.restype = UnmanagedVector
        L.execute.argtypes = [
            ctypes.c_void_p, ByteSliceView, ByteSliceView, ByteSliceView, ByteSliceView,
            Db, GoApi, GoQuerier, ctypes.c_uint64, ctypes.c_bool,
            ctypes.POINTER(GasReport), ctypes.POINTER(UnmanagedVector),
        ]
        # `query` has the same shape as `execute` minus the `info` argument:
        #   struct UnmanagedVector query(cache, checksum, env, msg, db, api,
        #                                 querier, gas_limit, print_debug,
        #                                 gas_report, error_msg)
        L.query.restype = UnmanagedVector
        L.query.argtypes = [
            ctypes.c_void_p, ByteSliceView, ByteSliceView, ByteSliceView,
            Db, GoApi, GoQuerier, ctypes.c_uint64, ctypes.c_bool,
            ctypes.POINTER(GasReport), ctypes.POINTER(UnmanagedVector),
        ]
        L.new_unmanaged_vector.restype = UnmanagedVector
        L.new_unmanaged_vector.argtypes = [ctypes.c_bool, ctypes.c_void_p, ctypes.c_size_t]
        L.destroy_unmanaged_vector.restype = None
        L.destroy_unmanaged_vector.argtypes = [UnmanagedVector]
        L.version_str.restype = ctypes.c_char_p
        L.release_cache.argtypes = [ctypes.c_void_p]

        self._new_vec = L.new_unmanaged_vector
        self._db = self._make_db()
        self._api = self._make_api()
        self._querier = self._make_querier()

    # -- callbacks ---------------------------------------------------------
    def _make_db(self):
        def read_db(db, gas_meter, gas_used, key, value_out, err_out):
            value_out[0] = self._new_vec(False, None, 0)
            return 0

        def write_db(db, gas_meter, gas_used, key, value, err_out):
            return 0

        def remove_db(db, gas_meter, gas_used, key, err_out):
            return 0

        def scan_db(db, gas_meter, gas_used, start, end, order, iterator_out, err_out):
            return 0

        vt = DbVtable()
        vt.read_db = DbRead(read_db)
        vt.write_db = DbWrite(write_db)
        vt.remove_db = DbRemove(remove_db)
        vt.scan_db = DbScan(scan_db)
        self._keep = [vt.read_db, vt.write_db, vt.remove_db, vt.scan_db]
        db = Db()
        db.gas_meter = None
        db.state = None
        db.vtable = vt
        return db

    def _make_api(self):
        def humanize(api, inp, out, err, gas_used):
            out[0] = self._new_vec(False, inp.ptr, inp.len)
            return 0

        def canonicalize(api, inp, out, err, gas_used):
            out[0] = self._new_vec(False, inp.ptr, inp.len)
            return 0

        def validate(api, inp, err, gas_used):
            return 0

        vt = GoApiVtable()
        vt.humanize_address = ApiInOut(humanize)
        vt.canonicalize_address = ApiInOut(canonicalize)
        vt.validate_address = ApiIn(validate)
        self._keep += [vt.humanize_address, vt.canonicalize_address, vt.validate_address]
        api = GoApi()
        api.state = None
        api.vtable = vt
        return api

    def _make_querier(self):
        def query(q, gas_limit, gas_used, request, result_out, err_out):
            result_out[0] = self._new_vec(False, None, 0)
            return 0

        vt = QuerierVtable()
        vt.query_external = QueryFn(query)
        self._keep.append(vt.query_external)
        q = GoQuerier()
        q.state = None
        q.vtable = vt
        return q

    # -- high level --------------------------------------------------------
    def version(self):
        return self.lib.version_str().decode()

    def init_cache(self, base_dir):
        cfg = json.dumps(
            {
                "wasm_limits": {
                    "initial_memory_limit_pages": 32,
                    "table_size_limit_elements": 100000,
                    "max_imports": 100,
                    "max_function_params": 100,
                },
                "cache": {
                    "base_dir": base_dir,
                    "available_capabilities": [
                        "iterator", "staking", "stargate", "cosmwasm_1_1", "cosmwasm_1_2",
                        "cosmwasm_1_3", "cosmwasm_1_4", "cosmwasm_2_0", "cosmwasm_2_1",
                        "cosmwasm_2_2", "ibc2",
                    ],
                    "memory_cache_size_bytes": 100 * 1024 * 1024,
                    "instance_memory_limit_bytes": 64 * 1024 * 1024,
                },
            }
        ).encode()
        err = UnmanagedVector()
        ptr = self.lib.init_cache(view(cfg), ctypes.byref(err))
        if not ptr:
            raise RuntimeError("init_cache failed: %s" % self._vec_str(err))
        return ctypes.c_void_p(ptr)

    def store_code(self, cache, wasm, checked=True):
        err = UnmanagedVector()
        out = self.lib.store_code(cache, view(wasm), checked, True, ctypes.byref(err))
        data = self._vec_bytes(out)
        self.lib.destroy_unmanaged_vector(out)
        if not data:
            raise RuntimeError("store_code failed: %s" % self._vec_str(err))
        return data

    def instantiate(self, cache, checksum, gas_limit):
        err = UnmanagedVector()
        rep = GasReport()
        out = self.lib.instantiate(
            cache, view(checksum), view(b"{}"), view(b"{}"), view(b"{}"),
            self._db, self._api, self._querier, gas_limit, False,
            ctypes.byref(rep), ctypes.byref(err),
        )
        return out, rep, err

    def execute(self, cache, checksum, gas_limit):
        err = UnmanagedVector()
        rep = GasReport()
        out = self.lib.execute(
            cache, view(checksum), view(b"{}"), view(b"{}"), view(b"{}"),
            self._db, self._api, self._querier, gas_limit, False,
            ctypes.byref(rep), ctypes.byref(err),
        )
        return out, rep, err

    def query(self, cache, checksum, gas_limit):
        """Runs the contract's `query` entry point (the one behind the gRPC
        `SmartContractState` query).  Same shape as `execute` minus `info`."""
        err = UnmanagedVector()
        rep = GasReport()
        out = self.lib.query(
            cache, view(checksum), view(b"{}"), view(b"{}"),
            self._db, self._api, self._querier, gas_limit, False,
            ctypes.byref(rep), ctypes.byref(err),
        )
        return out, rep, err

    @staticmethod
    def _vec_bytes(v):
        if v.is_none or not v.len:
            return b""
        return ctypes.string_at(v.ptr, v.len)

    @staticmethod
    def _vec_str(v):
        try:
            return VM._vec_bytes(v).decode(errors="replace")
        except Exception:
            return "<unreadable>"


# --------------------------------------------------------------------------
# driver
# --------------------------------------------------------------------------


def run_once(wasm, stack_size, gas_limit=1 << 62, do_execute=True):
    """Runs the contract in a thread with a controlled native stack size.

    Returns a dict with the outcome.
    """
    base = tempfile.mkdtemp(prefix="wasmvm-poc-")
    out = {"crash": False}
    state = {}

    def target():
        vm = VM()
        state["version"] = vm.version()
        cache = vm.init_cache(base)
        try:
            checksum = vm.store_code(cache, wasm, checked=True)
            state["checksum"] = checksum.hex()
            out["stored"] = True
        except Exception as exc:
            # Static validation / compatibility rejection happens here.
            out["store_err"] = repr(exc)
            out["stored"] = "rejected"
            return
        try:
            res, rep, err = vm.instantiate(cache, checksum, gas_limit)
            if res.is_none:
                out["instantiate_err"] = vm._vec_str(err)
                out["stored"] = "instantiate-failed"
                return
            state["instantiate_gas"] = rep.used_internally
            if do_execute:
                res2, rep2, err2 = vm.execute(cache, checksum, gas_limit)
                out["gas"] = rep2.used_internally
                out["remaining"] = rep2.remaining
                # The C API can return a *present but empty* response vector
                # together with a non-empty error vector.  The error must be
                # recorded unconditionally, otherwise failures are silently
                # classified as successes.
                errtxt = vm._vec_str(err2)
                if errtxt:
                    out["execute_err"] = errtxt
                if res2.is_none:
                    out["resp_none"] = True
                else:
                    out["resp"] = vm._vec_bytes(res2)[:120].decode(errors="replace")
            out["done"] = True
        except Exception as exc:  # pragma: no cover
            out["exception"] = repr(exc)

    if stack_size:
        threading.stack_size(stack_size)
    t = threading.Thread(target=target)
    t.start()
    t.join()
    shutil.rmtree(base, ignore_errors=True)
    out.update(state)
    out["crash"] = CRASH["hit"]
    if CRASH["hit"]:
        out["fault_addr"] = CRASH["addr"]
        out["rsp"] = CRASH["rsp"]
        out["rip"] = CRASH["rip"]
        out["thread_stack_sp"] = CRASH["stack_sp"]
        out["thread_stack_size"] = CRASH["stack_size"]
    return out


def describe(tag, r):
    if r.get("crash"):
        sp = r.get("thread_stack_sp") or 0
        addr = r.get("fault_addr") or 0
        size = r.get("thread_stack_size") or 0
        below = addr < sp
        print(
            "[%s] *** SIGSEGV inside JIT-ed wasm code ***\n"
            "        fault_addr   = %s\n"
            "        thread stack = [%s, %s)  (size %s)\n"
            "        fault %s the stack guard page\n"
            "        rsp at fault = %s"
            % (
                tag,
                hex(addr),
                hex(sp),
                hex(sp + size),
                size,
                "is BELOW" if below else "is inside",
                hex(r.get("rsp") or 0),
            )
        )
        return "CRASH"
    if "exception" in r:
        print("[%s] harness exception: %s" % (tag, r["exception"]))
        return "ERROR"
    if r.get("instantiate_err"):
        print("[%s] instantiate error: %s" % (tag, r["instantiate_err"][:400]))
        return "INSTANTIATE_ERR"
    if r.get("execute_err"):
        print(
            "[%s] completed WITHOUT crash (execute returned host error: %s)"
            % (tag, r["execute_err"][:160])
        )
        return "OK"
    print(
        "[%s] completed WITHOUT crash (resp=%s gas_used=%s)"
        % (tag, str(r.get("resp"))[:80], r.get("gas"))
    )
    return "OK"


CASES = {
    # name               params prefix explicit_else iterations expected
    "trigger":          (1, 4, False, 400000, 0),
    "control_else":     (1, 4, True, 400000, 42),
    "control_noparams": (0, 4, False, 400000, 0),
    "trigger_p0":       (1, 0, False, 400000, 0),
    "trigger_p31":      (1, 31, False, 400000, 0),
}


def run_case_subprocess(spec, stack_size, gas_limit):
    """Runs one case in a child process (a SIGSEGV would kill the parent)."""
    import subprocess

    cmd = [
        sys.executable,
        os.path.abspath(__file__),
        "case",
        json.dumps(spec),
        str(stack_size),
        str(gas_limit),
    ]
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"

    if mode == "case":
        install_segv_handler()
        spec = json.loads(sys.argv[2])
        stack_size = int(sys.argv[3]) if len(sys.argv) > 3 else (1 << 20)
        gas_limit = int(sys.argv[4]) if len(sys.argv) > 4 else (1 << 62)
        wasm = build_contract(
            iterations=spec.get("iterations", 400000),
            param_count=spec.get("params", 1),
            prefix_count=spec.get("prefix", 4),
            explicit_else=spec.get("explicit", False),
            use_params=spec.get("params", 1) > 0,
            expected=spec.get("expected", 0),
            shape=spec.get("shape", "upstream"),
        )
        r = run_once(wasm, stack_size, gas_limit=gas_limit)
        print("version=%s" % r.get("version"))
        print("stored=%s checksum=%s" % (r.get("stored"), r.get("checksum")))
        print("gas_used=%s" % r.get("gas"))
        sys.stdout.flush()
        status = describe(spec.get("name", "case"), r)
        print("STATUS=%s" % status)
        sys.stdout.flush()
        sys.exit(0 if status == "OK" else 3)

    if mode == "sweep":
        stack_size = int(os.environ.get("STACK_SIZE", 1 << 20))
        iters = int(os.environ.get("ITERS", 200000))
        gas_limit = int(os.environ.get("GAS_LIMIT", 1 << 62))
        print("libwasmvm:", LIB, VM().version())
        print("stack=%d bytes, iterations=%d" % (stack_size, iters))
        print("%-9s %-7s %-9s %-8s %-6s %s" % ("shape", "prefix", "explicit", "crash", "gas", "note"))
        rows = []
        for shape in ("upstream", "inline"):
            for prefix in (0, 4, 31, 32):
                for explicit in (False, True):
                    spec = {
                        "name": "%s/p%d/%s" % (shape, prefix, "else" if explicit else "implicit"),
                        "shape": shape,
                        "prefix": prefix,
                        "explicit": explicit,
                        "expected": 42 if explicit else 0,
                        "params": 1,
                        "iterations": iters,
                    }
                    rc, out, err = run_case_subprocess(spec, stack_size, gas_limit)
                    crash = "YES" if rc == 42 else "no"
                    gas = ""
                    for line in out.splitlines():
                        if line.startswith("gas_used="):
                            gas = line.split("=", 1)[1]
                    note = ""
                    for line in out.splitlines():
                        if line.startswith("[") and "***" in line:
                            note = line.strip()
                    rows.append((spec["name"], crash, gas, note))
                    print("%-9s %-7d %-9s %-8s %-6s %s" % (
                        shape, prefix, "explicit" if explicit else "implicit",
                        crash, gas, note[:60]))
                    sys.stdout.flush()
        crashed = [r for r in rows if r[1] == "YES"]
        print()
        print("cases with SIGSEGV: %d/%d" % (len(crashed), len(rows)))
        for r in crashed:
            print("   ", r[0])
        return 42 if crashed else 0

    # ---- parent: run every case in its own process ----------------------
    print("libwasmvm under test:", LIB)
    print("version string:", VM().version())
    stack_size = int(os.environ.get("STACK_SIZE", 1 << 20))
    print("native thread stack used for the VM call: %d bytes (%.1f MiB)"
          % (stack_size, stack_size / 1048576.0))
    print()
    rc_all = 0
    for case in ("trigger", "control_else", "control_noparams"):
        rc, out, err = run_case_subprocess(CASES[case], stack_size, 1 << 62)
        print("=" * 78)
        print("CASE %s   (exit code %d)" % (case, rc))
        print("-" * 78)
        if out.strip():
            print(out.strip())
        if err.strip():
            print(err.strip())
        if case == "trigger" and rc == 42:
            rc_all = 42
    print("=" * 78)
    print("overall:", "VULNERABLE (SIGSEGV in JIT-ed wasm code)" if rc_all == 42 else "no crash")
    return rc_all


if __name__ == "__main__":
    sys.exit(main() or 0)
