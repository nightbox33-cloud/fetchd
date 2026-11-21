import ctypes, json, os, tempfile, shutil, sys

LIB_PATH = os.environ.get("LIBWASMVM_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "libwasmvm.x86_64.so"))

class ByteSliceView(ctypes.Structure):
    _fields_ = [("is_nil", ctypes.c_bool), ("ptr", ctypes.c_void_p), ("len", ctypes.c_size_t)]

class UnmanagedVector(ctypes.Structure):
    _fields_ = [("is_none", ctypes.c_bool), ("ptr", ctypes.c_void_p), ("len", ctypes.c_size_t), ("cap", ctypes.c_size_t)]

class GasReport(ctypes.Structure):
    _fields_ = [("limit", ctypes.c_uint64), ("remaining", ctypes.c_uint64), ("used_externally", ctypes.c_uint64), ("used_internally", ctypes.c_uint64)]

class DbVtable(ctypes.Structure):
    _fields_ = [("read_db", ctypes.c_void_p), ("write_db", ctypes.c_void_p), ("remove_db", ctypes.c_void_p), ("scan_db", ctypes.c_void_p)]

class Db(ctypes.Structure):
    _fields_ = [("gas_meter", ctypes.c_void_p), ("state", ctypes.c_void_p), ("vtable", DbVtable)]

class GoApiVtable(ctypes.Structure):
    _fields_ = [("humanize_address", ctypes.c_void_p), ("canonicalize_address", ctypes.c_void_p), ("validate_address", ctypes.c_void_p)]

class GoApi(ctypes.Structure):
    _fields_ = [("state", ctypes.c_void_p), ("vtable", GoApiVtable)]

class QuerierVtable(ctypes.Structure):
    _fields_ = [("query_external", ctypes.c_void_p)]

class GoQuerier(ctypes.Structure):
    _fields_ = [("state", ctypes.c_void_p), ("vtable", QuerierVtable)]

# Need dummy callbacks that return GoError_None (0) and set *gas_used=0, and leave output vectors as None (default)
# Signatures:
# read_db(db, gas_meter, gas_used, key, value_out, err_msg_out) -> i32
# write_db(db, gas_meter, gas_used, key, value, err_msg_out) -> i32
# remove_db(db, gas_meter, gas_used, key, err_msg_out) -> i32
# scan_db(db, gas_meter, gas_used, start, end, order, iterator_out, err_msg_out) -> i32
# humanize_address(api, input, humanized_out, err_out, gas_used) -> i32
# canonicalize_address(api, input, canonicalized_out, err_out, gas_used) -> i32
# validate_address(api, input, err_out, gas_used) -> i32
# query_external(querier, gas_limit, gas_used, request, result_out, err_out) -> i32
# For our PoC contract that never calls env.*, these should never be invoked. But hackatom DOES call them (addr_validate etc).
# So for hackatom test we need functional dummies. For PoC contract (no imports), dummies never called, so NULL vtables would work.
# Let's implement dummies that return 0 (GoError_None) - for hackatom, addr_validate returning success with no output may still work? Let's see.
# Actually hackatom instantiate calls addr_validate on verifier/beneficiary. If dummy returns None without setting output, Rust will try to consume output (None) -> may error but not panic.
# Better to implement minimal functional dummies using libwasmvm's new_unmanaged_vector to create outputs.
# Simpler: for now, test with PoC contract (no imports) using NULL vtables, and skip hackatom.

# Dummy callbacks (never called for PoC, but provide non-NULL to avoid panic if called)
# We need to keep CFUNCTYPE objects alive.
CALLBACK_TYPE_DB_READ = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64), ctypes.c_void_p, ctypes.POINTER(UnmanagedVector), ctypes.POINTER(UnmanagedVector))
# Actually U8SliceView is struct {bool, ptr, len} - need to define
class U8SliceView(ctypes.Structure):
    _fields_ = [("is_none", ctypes.c_bool), ("ptr", ctypes.c_void_p), ("len", ctypes.c_size_t)]

# Redefine with correct types
DB_READ_T = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64), U8SliceView, ctypes.POINTER(UnmanagedVector), ctypes.POINTER(UnmanagedVector))
DB_WRITE_T = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64), U8SliceView, U8SliceView, ctypes.POINTER(UnmanagedVector))
DB_REMOVE_T = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64), U8SliceView, ctypes.POINTER(UnmanagedVector))
# scan_db: (db, gas_meter, gas_used, start, end, order, iterator_out, err_out)
# GoIter struct: {gas_meter, reference {call_id, iterator_id}, vtable {next, next_key, next_value}}
class IteratorReference(ctypes.Structure):
    _fields_ = [("call_id", ctypes.c_uint64), ("iterator_id", ctypes.c_uint64)]
class IteratorVtable(ctypes.Structure):
    _fields_ = [("next", ctypes.c_void_p), ("next_key", ctypes.c_void_p), ("next_value", ctypes.c_void_p)]
class GoIter(ctypes.Structure):
    _fields_ = [("gas_meter", ctypes.c_void_p), ("reference", IteratorReference), ("vtable", IteratorVtable)]
DB_SCAN_T = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64), U8SliceView, U8SliceView, ctypes.c_int32, ctypes.POINTER(GoIter), ctypes.POINTER(UnmanagedVector))
API_HUMANIZE_T = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, U8SliceView, ctypes.POINTER(UnmanagedVector), ctypes.POINTER(UnmanagedVector), ctypes.POINTER(ctypes.c_uint64))
API_CANON_T = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, U8SliceView, ctypes.POINTER(UnmanagedVector), ctypes.POINTER(UnmanagedVector), ctypes.POINTER(ctypes.c_uint64))
API_VALIDATE_T = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, U8SliceView, ctypes.POINTER(UnmanagedVector), ctypes.POINTER(ctypes.c_uint64))
QUERIER_T = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64), U8SliceView, ctypes.POINTER(UnmanagedVector), ctypes.POINTER(UnmanagedVector))

def dummy_db_read(db, gas_meter, gas_used, key, value_out, err_out):
    gas_used.contents.value = 0
    # value_out = None (is_none=True)
    value_out.contents.is_none = True
    value_out.contents.ptr = None
    value_out.contents.len = 0
    value_out.contents.cap = 0
    return 0  # GoError_None

def dummy_db_write(db, gas_meter, gas_used, key, value, err_out):
    gas_used.contents.value = 0
    return 0

def dummy_db_remove(db, gas_meter, gas_used, key, err_out):
    gas_used.contents.value = 0
    return 0

def dummy_db_scan(db, gas_meter, gas_used, start, end, order, iterator_out, err_out):
    gas_used.contents.value = 0
    # Return error? For now return GoError_User (5) to indicate no iterator? But PoC never calls scan.
    return 5

def dummy_humanize(api, inp, out, err_out, gas_used):
    gas_used.contents.value = 0
    # Return empty string? Need to create UnmanagedVector via new_unmanaged_vector. For now, set out to None and return User error.
    # But hackatom needs humanize to succeed. Let's just return User error for now; PoC doesn't need it.
    return 5

def dummy_canon(api, inp, out, err_out, gas_used):
    gas_used.contents.value = 0
    return 5

def dummy_validate(api, inp, err_out, gas_used):
    gas_used.contents.value = 0
    return 0  # success (no output needed)

def dummy_querier(querier, gas_limit, gas_used, request, result_out, err_out):
    gas_used.contents.value = 0
    return 5

# Keep references
_cb_read = DB_READ_T(dummy_db_read)
_cb_write = DB_WRITE_T(dummy_db_write)
_cb_remove = DB_REMOVE_T(dummy_db_remove)
_cb_scan = DB_SCAN_T(dummy_db_scan)
_cb_humanize = API_HUMANIZE_T(dummy_humanize)
_cb_canon = API_CANON_T(dummy_canon)
_cb_validate = API_VALIDATE_T(dummy_validate)
_cb_querier = QUERIER_T(dummy_querier)

def make_db():
    return Db(None, None, DbVtable(ctypes.cast(_cb_read, ctypes.c_void_p), ctypes.cast(_cb_write, ctypes.c_void_p), ctypes.cast(_cb_remove, ctypes.c_void_p), ctypes.cast(_cb_scan, ctypes.c_void_p)))

def make_api():
    return GoApi(None, GoApiVtable(ctypes.cast(_cb_humanize, ctypes.c_void_p), ctypes.cast(_cb_canon, ctypes.c_void_p), ctypes.cast(_cb_validate, ctypes.c_void_p)))

def make_querier():
    return GoQuerier(None, QuerierVtable(ctypes.cast(_cb_querier, ctypes.c_void_p)))

def make_view(data: bytes):
    if data is None:
        return ByteSliceView(True, None, 0), None
    if len(data)==0:
        return ByteSliceView(False, None, 0), None
    buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    return ByteSliceView(False, ctypes.cast(buf, ctypes.c_void_p), len(data)), buf

def read_unmanaged(v: UnmanagedVector):
    if v.is_none:
        return None
    if v.cap == 0:
        return b""
    return ctypes.string_at(v.ptr, v.len)

def destroy_unmanaged(lib, v: UnmanagedVector):
    lib.destroy_unmanaged_vector(v)

def load_lib():
    lib = ctypes.CDLL(LIB_PATH)
    lib.version_str.restype = ctypes.c_char_p
    lib.version_str.argtypes = []
    lib.init_cache.restype = ctypes.c_void_p
    lib.init_cache.argtypes = [ByteSliceView, ctypes.POINTER(UnmanagedVector)]
    lib.release_cache.restype = None
    lib.release_cache.argtypes = [ctypes.c_void_p]
    lib.store_code.restype = UnmanagedVector
    lib.store_code.argtypes = [ctypes.c_void_p, ByteSliceView, ctypes.c_bool, ctypes.c_bool, ctypes.POINTER(UnmanagedVector)]
    lib.instantiate.restype = UnmanagedVector
    lib.instantiate.argtypes = [ctypes.c_void_p, ByteSliceView, ByteSliceView, ByteSliceView, ByteSliceView, Db, GoApi, GoQuerier, ctypes.c_uint64, ctypes.c_bool, ctypes.POINTER(GasReport), ctypes.POINTER(UnmanagedVector)]
    lib.execute.restype = UnmanagedVector
    lib.execute.argtypes = [ctypes.c_void_p, ByteSliceView, ByteSliceView, ByteSliceView, ByteSliceView, Db, GoApi, GoQuerier, ctypes.c_uint64, ctypes.c_bool, ctypes.POINTER(GasReport), ctypes.POINTER(UnmanagedVector)]
    lib.destroy_unmanaged_vector.restype = None
    lib.destroy_unmanaged_vector.argtypes = [UnmanagedVector]
    return lib

def init_cache(lib, base_dir):
    config = {
        "wasm_limits": {},
        "cache": {
            "base_dir": base_dir,
            "available_capabilities": ["staking","stargate","iterator","cosmwasm_1_1","cosmwasm_1_2","cosmwasm_1_3","cosmwasm_1_4","cosmwasm_2_0","cosmwasm_2_1","cosmwasm_2_2"],
            "memory_cache_size_bytes": 100*1024*1024,
            "instance_memory_limit_bytes": 32*1024*1024
        }
    }
    cfg_bytes = json.dumps(config).encode()
    view, buf = make_view(cfg_bytes)
    errmsg = UnmanagedVector()
    cache = lib.init_cache(view, ctypes.byref(errmsg))
    if not cache:
        err = read_unmanaged(errmsg)
        print(f"init_cache failed: {err}")
        raise RuntimeError(f"init_cache failed: {err}")
    print(f"init_cache OK cache={hex(cache)} version={lib.version_str()}")
    return cache

def store_code(lib, cache, wasm, checked=True):
    view, buf = make_view(wasm)
    errmsg = UnmanagedVector()
    checksum_vec = lib.store_code(cache, view, checked, True, ctypes.byref(errmsg))
    checksum = read_unmanaged(checksum_vec)
    err = read_unmanaged(errmsg)
    print(f"store_code checked={checked} checksum={checksum.hex() if checksum else None} err={err}")
    destroy_unmanaged(lib, checksum_vec)
    if not errmsg.is_none:
        destroy_unmanaged(lib, errmsg)
    if checksum is None or len(checksum)==0:
        raise RuntimeError(f"store_code failed err={err}")
    return checksum

def call_entry(lib, cache, checksum, env, info, msg, gas_limit=500_000_000_000, is_execute=False):
    cs_view, _ = make_view(checksum)
    env_view, _ = make_view(env)
    info_view, _ = make_view(info)
    msg_view, _ = make_view(msg)
    db = make_db()
    api = make_api()
    querier = make_querier()
    gas_report = GasReport()
    errmsg = UnmanagedVector()
    fn = lib.execute if is_execute else lib.instantiate
    res_vec = fn(cache, cs_view, env_view, info_view, msg_view, db, api, querier, gas_limit, False, ctypes.byref(gas_report), ctypes.byref(errmsg))
    res = read_unmanaged(res_vec)
    err = read_unmanaged(errmsg)
    print(f"{'execute' if is_execute else 'instantiate'} res={res[:500] if res else None} err={err} gas_used_internally={gas_report.used_internally} remaining={gas_report.remaining}")
    destroy_unmanaged(lib, res_vec)
    if not errmsg.is_none:
        destroy_unmanaged(lib, errmsg)
    return res, err, gas_report

if __name__ == "__main__":
    from gen_wat2 import make_wat
    from wasmtime import wat2wasm
    lib = load_lib()
    print(f"version: {lib.version_str()}")
    tmpdir = tempfile.mkdtemp(prefix="wasmvm_poc_")
    print(f"tmpdir {tmpdir}")
    try:
        cache = init_cache(lib, tmpdir)
        # Test PoC minimal (1000 iterations, implicit-else false)
        wat = make_wat(param_count=2, prefix_count=32, iterations=1000, explicit_else=False, condition=0, body="empty")
        wasm = wat2wasm(wat)
        print(f"WASM len {len(wasm)}")
        checksum = store_code(lib, cache, wasm, checked=True)
        env = json.dumps({"block":{"height":123,"time":"1578939743987654321","chain_id":"foobar"},"transaction":{"index":4,"hash":"AABBCCDDEEFF0011AABBCCDDEEFF0011AABBCCDDEEFF0011AABBCCDDEEFF0011"},"contract":{"address":"contract"}}).encode()
        info = json.dumps({"sender":"creator","funds":[{"denom":"ATOM","amount":"100"}]}).encode()
        msg = b'{}'
        res, err, gas = call_entry(lib, cache, checksum, env, info, msg, is_execute=False)
        print(f"PoC instantiate done res={res}")
        res2, err2, gas2 = call_entry(lib, cache, checksum, env, info, msg, is_execute=True)
        print(f"PoC execute done res={res2}")
        lib.release_cache(cache)
        print("release_cache OK")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
