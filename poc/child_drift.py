import os

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_wat4 import make_wat
from wasmtime import wat2wasm
from harness2 import load_lib, init_cache, store_code, call_entry
import tempfile, shutil, json

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cfg.json')) as f:
    cfg = json.load(f)
lib = load_lib()
tmpdir = tempfile.mkdtemp(prefix="wasmvm_poc_")
try:
    cache = init_cache(lib, tmpdir)
    wat = make_wat(**cfg)
    wasm = wat2wasm(wat)
    print(f"WASM len {len(wasm)}", flush=True)
    checksum = store_code(lib, cache, wasm, checked=True)
    print(f"store_code OK", flush=True)
    env = json.dumps({"block":{"height":123,"time":"1578939743987654321","chain_id":"foobar"},"transaction":{"index":4,"hash":"AABBCCDDEEFF0011AABBCCDDEEFF0011AABBCCDDEEFF0011AABBCCDDEEFF0011"},"contract":{"address":"contract"}}).encode()
    info = json.dumps({"sender":"creator","funds":[{"denom":"ATOM","amount":"100"}]}).encode()
    msg = b'{}'
    res, err, gas = call_entry(lib, cache, checksum, env, info, msg, is_execute=False)
    print(f"instantiate OK res={res}", flush=True)
    res2, err2, gas2 = call_entry(lib, cache, checksum, env, info, msg, is_execute=True)
    print(f"execute res={res2} err={err2} gas={gas2.used_internally}", flush=True)
    lib.release_cache(cache)
    print("DONE EXIT=0", flush=True)
finally:
    shutil.rmtree(tmpdir, ignore_errors=True)
