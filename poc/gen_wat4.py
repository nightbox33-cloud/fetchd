from wasmtime import wat2wasm

RESP = b'{"ok":{"messages":[],"attributes":[],"events":[]}}'

def make_wat(param_count=1, prefix_count=32, iterations=400000, explicit_else=False, condition=0, body="empty"):
    types = " i64" * param_count
    block_type = "" if param_count==0 else "(type $pass)"
    pushes = "local.get $value\n" * (prefix_count + param_count)
    drops = "drop\n" * prefix_count
    if body=="empty":
        body_wat = ""
        true_result = 123
    elif body=="replace":
        body_wat = ("drop\n" * param_count) + ("i64.const 42\n" * param_count)
        true_result = 42
    elif body=="branch":
        body_wat = "br 0"
        true_result = 123
    else:
        body_wat = ""
        true_result = 123
    expected = 123 if condition==0 else true_result
    checks = ""
    for _ in range(param_count):
        checks += "local.get $expected i64.ne if unreachable end\n"
    else_text = "else" if explicit_else else ""
    # make_response with manual copy loop (no bulk memory)
    # data bytes as i32.const sequence? Instead, embed RESP as data segment and copy via loop.
    # Simpler: generate WAT that stores each byte individually via i32.store8 with offset.
    # RESP len 50, generate 50 store8 instructions.
    store_seq = ""
    for i, b in enumerate(RESP):
        store_seq += f"(i32.store8 (i32.add (local.get $data_ptr) (i32.const {i})) (i32.const {b}))\n"
    wat = f"""(module
  (type $pass (func (param{types}) (result{types})))
  (memory (export "memory") 1)
  (global $heap_ptr (mut i32) (i32.const 2048))
  (func $probe)
  (func $allocate (export "allocate") (param i32) (result i32)
    (local $size i32)
    (local $region_ptr i32)
    (local $data_ptr i32)
    (local.get 0)
    (local.set $size)
    (global.get $heap_ptr)
    (local.set $region_ptr)
    (local.get $region_ptr)
    (i32.const 12)
    (i32.add)
    (local.set $data_ptr)
    (local.get $region_ptr)
    (local.get $data_ptr)
    (i32.store offset=0)
    (local.get $region_ptr)
    (local.get $size)
    (i32.store offset=4)
    (local.get $region_ptr)
    (local.get $size)
    (i32.store offset=8)
    (global.set $heap_ptr
      (i32.add (global.get $heap_ptr)
        (i32.add (i32.const 12) (local.get $size))))
    (local.get $region_ptr)
  )
  (func (export "deallocate") (param i32)
  )
  (func (export "interface_version_8")
  )
  (func $make_response (result i32)
    (local $region_ptr i32)
    (local $data_ptr i32)
    (i32.const {len(RESP)})
    (call $allocate)
    (local.set $region_ptr)
    (local.get $region_ptr)
    (i32.load offset=0)
    (local.set $data_ptr)
    {store_seq}
    (local.get $region_ptr)
  )
  (func (export "instantiate") (param i32 i32 i32) (result i32)
    (call $make_response)
  )
  (func (export "execute") (param i32 i32 i32) (result i32)
    (local $value i64)
    (local $expected i64)
    (local $remaining i32)
    (local $condition i32)
    (i64.const 123)
    (local.set $value)
    (i64.const {expected})
    (local.set $expected)
    (i32.const {condition})
    (local.set $condition)
    (i32.const {iterations})
    (local.set $remaining)
    (loop
      {pushes}
      (local.get $condition)
      if {block_type}
      {body_wat}
      {else_text}
      end
      {checks}
      {drops}
      (call $probe)
      (local.get $remaining)
      (i32.const 1)
      (i32.sub)
      (local.tee $remaining)
      (br_if 0)
    )
    (call $make_response)
  )
)
"""
    return wat

if __name__ == "__main__":
    for cfg in [
        dict(param_count=1, prefix_count=32, iterations=1000, explicit_else=False, condition=0, body="empty"),
    ]:
        wat = make_wat(**cfg)
        wasm = wat2wasm(wat)
        print(f"WASM len {len(wasm)}")
        from wasmtime import Engine, Module
        engine = Engine()
        mod = Module(engine, wasm)
        print("exports:", [e.name for e in mod.exports])
        print("imports:", [(i.module, i.name) for i in mod.imports])
        print("OK")
