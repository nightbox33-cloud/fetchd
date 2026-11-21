from wasmtime import wat2wasm

RESP_JSON = b'{"ok":{"messages":[],"attributes":[],"events":[]}}'

def make_wat(drift_iters=10, probe_params=50, explicit_else=False, condition=0):
    param_count=1
    prefix_count=32
    types = " i64" * param_count
    block_type = "(type $pass)"
    pushes = "local.get $value\n" * (prefix_count + param_count)
    drops = "drop\n" * prefix_count
    body_wat = ""
    expected = 123
    checks = "local.get $expected i64.ne if unreachable end\n"
    else_text = "else" if explicit_else else ""
    store_seq_json = ""
    for i, b in enumerate(RESP_JSON):
        store_seq_json += "(i32.store8 (i32.add (local.get $data_ptr) (i32.const " + str(i) + ")) (i32.const " + str(b) + "))\n"
    probe_param_types = " i64" * probe_params
    ret_idx = 5 if probe_params >= 6 else 0
    probe_body = "local.get " + str(ret_idx)
    big_args = "local.get $value\n" * probe_params
    wat = "(module\n"
    wat += "  (type $pass (func (param" + types + ") (result" + types + ")))\n"
    wat += '  (memory (export "memory") 1)\n'
    wat += "  (global $heap_ptr (mut i32) (i32.const 2048))\n"
    wat += "  (func $probe_drift (result i64)\n    i64.const 0\n  )\n"
    wat += "  (func $probe_big (param" + probe_param_types + ") (result i64)\n    " + probe_body + "\n  )\n"
    wat += '  (func $allocate (export "allocate") (param i32) (result i32)\n'
    wat += "    (local $size i32)\n    (local $region_ptr i32)\n    (local $data_ptr i32)\n"
    wat += "    (local.get 0)\n    (local.set $size)\n"
    wat += "    (global.get $heap_ptr)\n    (local.set $region_ptr)\n"
    wat += "    (local.get $region_ptr)\n    (i32.const 12)\n    (i32.add)\n    (local.set $data_ptr)\n"
    wat += "    (local.get $region_ptr)\n    (local.get $data_ptr)\n    (i32.store offset=0)\n"
    wat += "    (local.get $region_ptr)\n    (local.get $size)\n    (i32.store offset=4)\n"
    wat += "    (local.get $region_ptr)\n    (local.get $size)\n    (i32.store offset=8)\n"
    wat += "    (global.set $heap_ptr\n      (i32.add (global.get $heap_ptr)\n        (i32.add (i32.const 12) (local.get $size))))\n"
    wat += "    (local.get $region_ptr)\n  )\n"
    wat += '  (func (export "deallocate") (param i32)\n  )\n'
    wat += '  (func (export "interface_version_8")\n  )\n'
    wat += "  (func $make_response_json (result i32)\n"
    wat += "    (local $region_ptr i32)\n    (local $data_ptr i32)\n"
    wat += "    (i32.const " + str(len(RESP_JSON)) + ")\n    (call $allocate)\n"
    wat += "    (local.set $region_ptr)\n"
    wat += "    (local.get $region_ptr)\n    (i32.load offset=0)\n    (local.set $data_ptr)\n"
    wat += "    " + store_seq_json + "\n"
    wat += "    (local.get $region_ptr)\n  )\n"
    wat += "  (func $make_response_8 (param i64) (result i32)\n"
    wat += "    (local $region_ptr i32)\n    (local $data_ptr i32)\n"
    wat += "    (i32.const 8)\n    (call $allocate)\n"
    wat += "    (local.set $region_ptr)\n"
    wat += "    (local.get $region_ptr)\n    (i32.load offset=0)\n    (local.set $data_ptr)\n"
    wat += "    (local.get $data_ptr)\n    (local.get 0)\n    (i64.store offset=0)\n"
    wat += "    (local.get $region_ptr)\n  )\n"
    wat += '  (func (export "instantiate") (param i32 i32 i32) (result i32)\n    (call $make_response_json)\n  )\n'
    wat += '  (func (export "execute") (param i32 i32 i32) (result i32)\n'
    wat += "    (local $value i64)\n    (local $expected i64)\n    (local $remaining i32)\n    (local $condition i32)\n    (local $probe_ret i64)\n"
    wat += "    (i64.const 123)\n    (local.set $value)\n"
    wat += "    (i64.const " + str(expected) + ")\n    (local.set $expected)\n"
    wat += "    (i32.const " + str(condition) + ")\n    (local.set $condition)\n"
    wat += "    (i32.const " + str(drift_iters) + ")\n    (local.set $remaining)\n"
    wat += "    (loop\n"
    wat += "      " + pushes + "\n"
    wat += "      (local.get $condition)\n"
    wat += "      if " + block_type + "\n"
    wat += "      " + body_wat + "\n"
    wat += "      " + else_text + "\n"
    wat += "      end\n"
    wat += "      " + checks + "\n"
    wat += "      " + drops + "\n"
    wat += "      (call $probe_drift)\n      (drop)\n"
    wat += "      (local.get $remaining)\n      (i32.const 1)\n      (i32.sub)\n      (local.tee $remaining)\n      (br_if 0)\n"
    wat += "    )\n"
    wat += "    " + big_args + "\n"
    wat += "    (call $probe_big)\n    (local.set $probe_ret)\n"
    wat += "    (local.get $probe_ret)\n    (call $make_response_8)\n"
    wat += "  )\n)\n"
    return wat

if __name__ == "__main__":
    for d, pp in [(10, 50), (100, 50), (1000, 50)]:
        wat = make_wat(drift_iters=d, probe_params=pp)
        wasm = wat2wasm(wat)
        print("drift=" + str(d) + " probe=" + str(pp) + " WASM len " + str(len(wasm)))
        from wasmtime import Engine, Module
        engine = Engine()
        mod = Module(engine, wasm)
        print("exports:", [e.name for e in mod.exports])
        print("OK")
