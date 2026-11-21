# Auditoría ofensiva — fetchhub-4 (fetchd v0.15.1) — Motor Wasm

**Fecha:** 2026-11-21
**Objetivo:** demostrar (o refutar) un escape de sandbox/VM en producción, permissionless y con PoC local reproducible.
**Método:** clonado de repos de la fundación + verificación de pin + PoC en Python/ctypes contra el artefacto binario exacto de producción. Sin RPC.

---

## 0. Veredicto

**CRÍTICO CONFIRMADO (N-day, sin parche en cadena, permissionless).**

fetchd v0.15.1 (`ae12a4fc8886b6bd45f4c70fb4973cd065462ad0`) enlaza
`libwasmvm` **v3.0.8-rc.3** (`fetchai/priv_wasmvm_sec@d89faf1`), construido con
**cosmwasm-vm 3.0.10-rc.3 + wasmer-compiler-singlepass 7.4.2**.
Esa versión está en el rango afectado de **GHSA-v2h8-j899-r676**
(CVSS 10.0, publicado 2026-11-02): el lowering de `if` tipado con parámetros de
bloque y `else` omitido deja la pila nativa desalineada **8 bytes por ejecución**,
lo que el mantenedor describe como corrupción de pila nativa y escape del
sandbox con ejecución de código nativo.

La superficie sigue abierta: el génesis productivo declara
`code_upload_access: Everybody` e `instantiate_default_permission: Everybody`,
y no existe propuesta de upgrade posterior en los repos ni en `app/upgrades.go`.

En esta auditoría se reprodujo localmente, contra el `.so` de producción:

- `store_code(checked=true)` **acepta** el módulo malicioso (misma validación que `MsgStoreCode`).
- `instantiate` + `execute` **compilan y ejecutan** el módulo con Singlepass.
- La rama falsa del `if` sin `else` **fuga exactamente 8 bytes de RSP por iteración**.
- El primer trap ocurre en la iteración **131018**; `131018 × 8 = 1.048.144 B ≈ 1 MiB`
  (= `DEFAULT_STACK_SIZE` de Wasmer 7.4.2), con un residuo de 432 B de prólogo/locales.

No se completó la fase final de weaponización (secuestro de flujo de control) en
este entorno; el propio advisory documenta que el reporter original obtuvo
ejecución de código nativo sobre wasmvm 3.0.8 / Wasmer 7.4.2 en Linux x86-64.
Ver §4.6 para el alcance exacto de lo probado y lo no probado.

---

## 1. Requisito previo: fundación, repos y despliegue (sin RPC)

### 1.1 Organización y espacios

| Espacio | Estado |
|---|---|
| GitHub `fetchai` | 99 repos públicos, inventario completo en `poc/audit/repos_page1.json` y pin por repo en `poc/audit/repos_pinned.json` |
| GitHub `CosmWasm` | `wasmvm`, `wasmd`, `cosmwasm`, `advisories` (CWA) — públicos |
| GitHub `wasmerio` | `wasmer` + advisories de seguridad — público |
| Repo privado | `CosmWasm/priv_cosmwasm` (referenciado en `priv_wasmvm_sec/libwasmvm/Cargo.toml`, `[patch.crates-io]`) → **404, bloqueado** |

### 1.2 Repos clonados y commits exactos (fuente de verdad)

| Repo | Commit / tag | Rol |
|---|---|---|
| `fetchai/fetchd` | `ae12a4fc8886b6bd45f4c70fb4973cd065462ad0` (master, tag v0.15.1) | binario en producción |
| `fetchai/priv_wasmvm_sec` | `d89faf180d3fb5de09b4ba59099844cc0a7a2632` (= v3.0.8-rc.3) | libwasmvm enlazada |
| `fetchai/priv_wasmd_sec` | `ab17af8e72692541e5eb1b57c2d5480ed8084300` (= v0.61.15-rc.3) | x/wasm fork |
| `CosmWasm/wasmvm` | tags v3.0.8 (ff80a1d), v3.0.9 (0538ebb) | upstream CGo/Rust |
| `CosmWasm/cosmwasm` | v3.0.10 (07fb015) | cosmwasm-vm upstream |
| `wasmerio/wasmer` | v7.4.2 (`7a48a071c7`), v7.5.0 (`82ff099e08`), fix `e5ca9b9380` | compilador Singlepass |
| `fetchai/genesis-fetchhub` | `cdc8ceda82ec7a2ae5b3dd97d7a2e51d8bf09170` | génesis y guías de upgrade |
| `fetchai/cosmos-sdk` (fork) | `5a24a3348e8366b55c0952711258e7f4eb37fec2` = v0.20.0 | replace del SDK |
| `fetchai/tokenfactory` | `88b3c8c0bf79c0e6230b3ab7b39528f78c10feb5` = v0.1.0 | módulo tokenfactory |
| `fetchai/cw-fetch-std` | `99e6ca281c1c18481b084b54585cb1dd6e6a7f3a` | librería de contratos |
| `fetchai/FIPs` | `43d6036820b08389c96dba1c6f4a5b78e5e711e8` | propuestas (FIP-006 block limits) |
| `fetchai/fetch-ethereum-bridge-v1` | `7ab886f55c7fc0476be5f64cf491b06066a95ae1` = v0.3.0 | puente ETH↔Fetch (contratos) |
| `fetchai/wasmswap-contracts` | `a9fd3f23e372f440ddbde6b3fc2a1803a7cd1af1` | DEX CosmWasm de ecosistema |
| `fetchai/multisig-forward` | `d54a403f04e28d5171a9e40feb1edc4ac539dc4e` | contrato multisig |

Clonado con `--depth 1` (y `--filter=blob:none --no-checkout` para repos de sólo
metadatos). El inventario completo de los 99 repos con SHA de la rama por defecto
está en `poc/audit/repos_pinned.json`.

### 1.3 Bloqueados / no cubiertos

- `CosmWasm/priv_cosmwasm` (privado): **no clonable**. Se acotó por dos vías
  independientes: (a) el espejo público `CosmWasm/cosmwasm@v3.0.10` es idéntico al
  tag privado `v3.0.10-rc.3` (`git diff v3.0.10-rc.3 v3.0.10` vacío en
  `packages/vm`, `packages/std`, `packages/crypto`); (b) se inspeccionó el
  binario `.so`/`.a` final, que es lo que realmente ejecuta la cadena.
- Repos de agentes/IA y documentación (p. ej. `uAgents`, `agents-aea`, `docs-archived`)
  no forman parte del runtime on-chain; quedan pinneados en el inventario pero
  fuera del alcance del motor Wasm.

### 1.4 Mapeo del despliegue sin RPC

- `go.mod:277-278`: `replace github.com/CosmWasm/wasmd => github.com/fetchai/priv_wasmd_sec v0.61.15-rc.3`;
  `replace github.com/CosmWasm/wasmvm/v3 => github.com/fetchai/priv_wasmvm_sec/v3 v3.0.8-rc.3`.
- `Makefile:171-190` (`install-static-v0.15.1`, usado por `musl.Dockerfile:108` y
  `docker-bake.hcl`): fija `WASMVM_VERSION := v3.0.8-rc.3` y verifica
  `sha256` de `libwasmvm_muslc.x86_64.a` = `ab1a878e…77497` y
  `aarch64` = `cc917523…54235` (coinciden con los blobs del fork).
- `app/app.go:694-712`: `wasmkeeper.NewKeeper(..., wasmtypes.VMConfig{}, wasmkeeper.BuiltInCapabilities(), ...)`
  — sin límites locales adicionales.
- `genesis-fetchhub/fetchhub-4/data/genesis_migrated_5300200.json`:
  - `wasm.params.code_upload_access.permission = "Everybody"`
  - `wasm.params.instantiate_default_permission = "Everybody"`
  - `wasm.params.max_wasm_code_size = "614400"`
  - `consensus_params.block = {max_bytes: 200000, max_gas: 2000000}`
  - 4 códigos y 4 contratos en el génesis.
- `genesis-fetchhub/fetchhub-4/10-software-upgrade-v0.15.1.md`:
  upgrade binary-only en la altura `29254333` (propuesta #41), versión esperada
  `v0.15.1-0-gae12a4f`, `wasmvm 3.0.8-rc.3`, sha256 del binario estático
  `89c5f1c0…e41ad` (x86_64) y `2b2848ab…db8b` (aarch64).
- `app/upgrades.go`: sólo manejadores `v0.15.0` y `v0.15.1` (el segundo vacío).
  No hay `v0.15.2` / `v0.16` en el repo.

---

## 2. Hallazgo crítico — GHSA-v2h8-j899-r676 en el binario de producción

### 2.1 Ubicación exacta

| Elemento | Valor |
|---|---|
| Aplicación | `fetchai/fetchd@ae12a4f` (v0.15.1), en producción desde altura 29254333 |
| Pin | `go.mod:278` → `priv_wasmvm_sec/v3 v3.0.8-rc.3` (`go.sum:941-942`) |
| Artefacto | `priv_wasmvm_sec@d89faf1/internal/api/libwasmvm.x86_64.so`, sha256 `0b18713c01c57a12d956614c98de6bd247d29b0649e7fa91a53b9444ce80ac32`; `version_str() = "3.0.8-rc.3"` |
| Dependencias | `libwasmvm/Cargo.lock`: `cosmwasm-vm 3.0.10-rc.3`, `wasmer-compiler-singlepass 7.4.2` |
| Config VM | `CosmWasm/cosmwasm@v3.0.10` `packages/vm/src/wasm_backend/engine.rs:54` → `wasmer::sys::Singlepass::new()`; multi-value habilitado en `packages/vm/src/parsed_wasm.rs:82-86` |
| Defecto | `wasmer@7.4.2` `lib/compiler-singlepass/src/codegen.rs`: `Operator::If` 2576, `Operator::Else` 2627, `Operator::End` 3766 |
| Fix upstream | `e5ca9b93809d744af8b33488a748a284d3d41955` (PR #7128, 2026-11-02), sin release estable; no presente en 7.4.2 **ni en 7.5.0** (`diff -u` vacío en `codegen.rs`) |

### 2.2 Mecánica del fallo (código)

El estándar multi-value permite `if` con firma `[t*] -> [t*]` sin `else`: si la
condición es falsa, los parámetros de entrada deben pasar intactos al resultado.

En `codegen.rs` de 7.4.2:

1. `Operator::If` llama a `allocate_return_slots_and_swap(param_types.len() + 1, return_types.len())`,
   que reserva slots de retorno **separados** de los slots de los parámetros y
   los intercambia en la pila de valores. Si un parámetro vive en memoria,
   `mapped_loc = dest` reutiliza el slot de retorno y el parámetro queda
   **aliasado** con él.
2. `Operator::If` emite un `jmp_on_condition(Equal, cond, 0, label_else)`.
3. `Operator::Else` (rama verdadera) hace `emit_return_values`, `release_locations`,
   `jmp` y **después** `emit_label(label_else)`. Es decir: la etiqueta del brazo
   falso se emite **después** del `truncate_stack` que devuelve el RSP a su sitio.
4. `Operator::End` sólo limpia/trunca en el camino de caída (rama verdadera). El
   salto de la rama falsa aterriza en `label_else`, ya después de la limpieza.

Resultado: en cada ejecución con condición falsa y parámetro spilled, el RSP real
queda **8 bytes por debajo** de lo que el compilador cree. El componente queda
`stack_ptr_in_bounds` hasta que RSP cruza la página de guarda del stack de
corrutina de 1 MiB, donde Wasmer convierte el SIGSEGV en `TrapCode::StackOverflow`.

El propio fix (`emit_if_block_end`) restaura las entradas y el estado de
asignación de pila antes de la colocación de resultados y la limpieza, y su test
`implicit_else_reclaims_inputs` ejecuta 400.000 iteraciones con un `probe` no
recursivo para exponer la fuga en la página de guarda — exactamente el
comportamiento que se reproduce aquí.

### 2.3 Condiciones de configuración (leídas del repo)

- `code_upload_access = Everybody` y `instantiate_default_permission = Everybody`
  (génesis productivo; también `MsgStoreCode`/`MsgInstantiateContract` estándar).
- Multi-value habilitado en el validador (`MULTI_VALUE | MUTABLE_GLOBAL | SATURATING_FLOAT_TO_INT | SIGN_EXTENSION | FLOATS | REFERENCE_TYPES`).
- `VMConfig{}` vacío en `app.go`, sin restricción local de propuestas.
- `max_wasm_code_size = 614400` B: el PoC completo pesa **1.371 bytes**.
- No hay plan de upgrade posterior (`app/upgrades.go`).

Con esto, cualquier cuenta con saldo mínimo para fees puede subir el contrato,
instanciarlo y ejecutarlo. No requiere gobernanza, validador ni permisos.

### 2.4 PoC local (reproducible)

Entorno: Linux x86_64, Python 3.11 + `wasmtime` (sólo como ensamblador WAT),
`ctypes` contra el `.so` de producción. El arnés replica la ABI C que usa Go
(`init_cache → store_code(checked=true) → instantiate → execute`) con vtables
dummy de DB/API/Querier (el módulo no importa `env.*`, por lo que nunca se llaman).

Módulo (generado por `poc/gen_wat4.py`), dentro de un `loop`:

```wat
local.get $value        ;; x33 = 32 valores prefijo + 1 parámetro de bloque
local.get $condition
if (type $pass)         ;; (func (param i64) (result i64))
end                     ;; else omitido (implícito)
```

Resultados (logs en `poc/logs/`):

| Caso | 200.000 iters | 131.018 iters | 300.000 iters |
|---|---|---|---|
| implícito, cond=0 (**trigger**) | **TRAP `call stack exhausted`** | **TRAP** | **TRAP** |
| implícito, cond=1 | OK | — | OK |
| explícito, cond=0 | OK | — | OK |
| sin parámetro de bloque | OK | — | — |
| prefijo 0/1/2 | OK | — | — |
| prefijo 4/8/16/24/32/48/64 | **TRAP** | **TRAP** (umbral idéntico) | — |
| cuerpo `replace` / `branch`, implícito, cond=0 | — | — | **TRAP** |
| cuerpo `branch`, explícito, cond=0 | — | — | OK |

- Umbral exacto: **131018** iteraciones (última OK 131017) → `131018 × 8 = 1.048.144 B`;
  `DEFAULT_STACK_SIZE` de Wasmer 7.4.2 = 1 MiB (`traphandlers.rs:53`, `ByteSize::mib(1)`);
  residuo 432 B = prólogo + locales + red zone.
- El umbral es **independiente del número de spills** (4 a 64 prefijos), lo que
  confirma una fuga constante de 8 B por ejecución y no un efecto de layout.
- Antes del trap: `store_code` OK, `instantiate` OK, `execute` devuelve
  `{"ok":...}` con gas 17.450.730 (implícito) vs 19.060.730 (explícito) a 1.000 iters.
- Error exacto en el trigger (132.000 iters): `Error calling the VM: Error executing
  Wasm: Wasmer runtime error: RuntimeError: call stack exhausted`, gas 2.140.653.050
  (`poc/logs/RUN-10-trap-exact.txt`).

Comandos:

```bash
pip install --break-system-packages wasmtime
export LIBWASMVM_PATH=$PWD/poc/libwasmvm.x86_64.so   # sha256 0b18713c…
python3 poc/sweep_controls.py     # trigger + controles (200k)
python3 poc/bisect_threshold.py   # umbral exacto = 131018
python3 poc/bisect_prefix.py      # umbral vs spills
python3 poc/sweep_variants.py     # cuerpo/condición/prefijo
```

### 2.5 Impacto

- **DoS determinista y permissionless:** un contrato de 1,4 KB revienta el stack
  de 1 MiB de la corrutina de ejecución de Wasmer en cada llamada; el trap se
  propaga como fallo de ejecución del contrato. Con bloques de 2.000.000 de gas
  (`consensus_params` del génesis) el coste para el atacante es una fracción del
  límite, repetible en cada bloque: base para detener producción de bloques
  (un contrato stored ejecuta en todos los nodos al ser llamado).
- **Primitiva de escape:** según el advisory y el fix, el RSP desincronizado
  provoca accesos nativos fuera del frame; el reporter original demostró
  ejecución de código nativo en wasmvm 3.0.8 / Wasmer 7.4.2 Linux x86-64.
- Una vez lograda la ejecución nativa, el proceso es el nodo validador: lectura
  de claves de firma, mutación de estado, acuñación no autorizada y pérdida de
  fondos de terceros. CWA-2026-006 (misma clase, Wasmer 5.0.6) lo califica como
  "Critical / Fund loss" y describe exactamente ese impacto.

### 2.6 Alcance exacto de la prueba local

Probado:

- El artefacto exacto de producción acepta el módulo con la misma validación
  que `MsgStoreCode` (`check_wasm` + multi-value + `interface_version_8` + exports).
- Ejecuta el módulo con Singlepass y la rama falsa del `if` implícito fuga 8 B
  de RSP por iteración hasta la página de guarda (1 MiB), de forma determinista.
- El comportamiento desaparece con `else` explícito, con condición verdadera,
  sin parámetro de bloque o sin spill (prefijo 0-2), igual que en el advisory.

No probado aquí:

- Secuestro de flujo de control / RCE completo. Las pruebas con argumentos de
  pila (`gen_wat7.py`: 50 argumentos tras 10/100/1.000/10.000 iteraciones de
  deriva) devuelven 123 correctamente: caller y callee permanecen consistentes
  en RSP, de modo que este arnés sólo demuestra la fuga/fuera-de-frame y el
  DoS, no un read/write nativo controlado.
- No se afirma RCE como resultado propio; se reporta como primitiva confirmada
  por el mantenedor (GHSA) sobre el mismo build downstream (wasmvm 3.0.8).

---

## 3. Hallazgos adicionales (mismo pin)

### 3.1 GHSA-xmhf-978x-4pcx — `Table` type mismatch (HIGH, ≤ 7.5.0)

Presente en 7.4.2. Requiere `table.set/grow/fill/copy` o `table.new`, que el
`Gatekeeper` de CosmWasm bloquea (`allow_feature_reference_types: false`), pero
el runtime embebido sigue conteniendo el defecto. **No explotable** en fetchhub-4
con la config actual de CosmWasm (instrucciones filtradas por middleware).

### 3.2 GHSA-37h3-8wp9-3hfx — Table embebida en VMContext desincronizada (LOW, ≤ 7.5.0)

Presente, misma mitigación por `Gatekeeper`. Informativo.

### 3.3 GHSA-8v4w-x73c-qp73 — Expansión SSE4.2 incorrecta de float en Singlepass x86_64 (MEDIUM, < 7.6.0)

**Alcanzable en este pin.** El `Gatekeeper` de CosmWasm 3.0.10 permite floats
(`allow_floats: true`, verificado en `gatekeeper.rs:65` y empíricamente:
un módulo con `f64.sub`/`f64.div` pasa `store_code(checked=true)`).
Impacto del advisory: los SPEC tests no se cumplen (resultados de `sub`/`div`,
predicados de comparación con NaN y conversiones float→int incorrectos).
Consecuencia on-chain: **divergencia de consenso** si un contrato almacenado
produce resultados distintos entre arquitecturas (x86_64 con SSE4.2 frente a
aarch64), lo que puede detener la cadena. No es robo de fondos directo, pero es
un riesgo de consenso real y no requiere rol privilegiado.

### 3.4 Comentario desactualizado en `Makefile:164-170`

Dice `v3.0.8-rc.2`; el pin real es `v3.0.8-rc.3` y los sha256 verifican rc.3.
Informativo (el build falla cerrado si no coincide).

### 3.5 `wasmd` fork: `go.mod` referencia `wasmvm/v3 v3.0.7`

El fork `priv_wasmd_sec@ab17af8` declara `v3.0.7` en su propio `go.mod`, pero el
binario final se resuelve en el `go.mod` de fetchd con el `replace` a
`priv_wasmvm_sec v3.0.8-rc.3` (MVS + replace). Verificado en el `.so` enlazado
(`version_str() = 3.0.8-rc.3`). No es un hallazgo; se documenta para evitar
falsos positivos al leer el fork aislado.

---

## 4. Descartes verificados (no críticos)

| Elemento | Por qué no es crítico |
|---|---|
| CWA-2026-006 (Wasmer 5.0.6) | Parcheado: el pin usa 7.4.2 |
| CWA-2026-001…005 | Versiones parcheadas (wasmvm 3.0.8-rc.3 / wasmd 0.61.15-rc.3) |
| GHSA-274f (LLVM `call_indirect`) | Backend LLVM no usado (Singlepass) |
| GHSA-c99m (memory64) | memory64 no habilitado por CosmWasm |
| GHSA-6936 / WASIX | WASIX no presente en wasmvm |
| GHSA-qw47 / r6j4 (atomics) | Threads bloqueados por `Gatekeeper` |
| tokenfactory `v0.1.0` | Checks de admin presentes en `Mint`, `Burn`, `ForceTransfer`, `ChangeAdmin`, `SetDenomMetadata`; ACL por capabilities |
| Puente `fetch-ethereum-bridge-v1@v0.3.0` | Contratos Ethereum + contrato CosmWasm con `access_control`; no se identificó ruta permissionless con impacto en escrow en el tiempo disponible |
| `wasmswap-contracts` | DEX de ecosistema; sin hallazgo crítico en revisión estática inicial |

---

## 5. Recomendación

1. **Upgrade inmediato** a una release de wasmvm con el fix `e5ca9b9380`
   (no existe release estable de Wasmer al 2026-11-21; CosmWasm debe publicar
   wasmvm con ese commit y wasmd correspondiente).
2. **Mitigación temporal:** rechazar multi-value en validación (el propio
   advisory lo indica) y deshabilitar `MsgStoreCode`, `MsgInstantiateContract`,
   `MsgInstantiateContract2`; invalidar la caché de módulos compilados
   (`wasmvm` cache) porque el código nativo vulnerable ya compilado no se repara
   con el upgrade.
3. Restringir `code_upload_access` e `instantiate_default_permission` a
   gobernanza/allowlist mientras no haya parche.
4. Revisar si existen contratos ya subidos que usen `if` con parámetros de
   bloque (el atacante puede haberlos dejado plantados antes del parche).

---

## 6. Registro de auditoría

### 6.1 Repos clonados (commit exacto)

Ver §1.2. Inventario completo de los 99 repos de `fetchai` con SHA:
`poc/audit/repos_pinned.json`.

### 6.2 Archivos de config/genesis/deploy inspeccionados

- `fetchd`: `go.mod`, `go.sum`, `Makefile` (110-200), `musl.Dockerfile` (90-130),
  `docker-bake.hcl`, `app/app.go` (630-720), `app/upgrades.go`, `app/ante.go`.
- `priv_wasmvm_sec`: `libwasmvm/Cargo.toml`, `libwasmvm/Cargo.lock`,
  `internal/api/bindings.h`, `internal/api/lib.go`, `internal/api/callbacks.go`,
  `.so`/`.a` (hashes).
- `cosmwasm@v3.0.10`: `packages/vm/src/compatibility.rs`, `parsed_wasm.rs`,
  `wasm_backend/engine.rs`, `wasm_backend/gatekeeper.rs`, `config.rs`.
- `wasmer@7.4.2`: `lib/compiler-singlepass/src/{codegen,machine,machine_x64}.rs`,
  `lib/vm/src/trap/traphandlers.rs`.
- `wasmer@7.5.0`: diff completo de `lib/compiler-singlepass/src`.
- `genesis-fetchhub/fetchhub-4`: `10-software-upgrade-v0.15.1.md`,
  `data/genesis_migrated_5300200.json`, `data/genesis_export_5300200.json`.
- `FIPs`: `FIPs/fip-006.md`.
- `tokenfactory@v0.1.0`: `x/tokenfactory/keeper/{msg_server,admins,createdenom}.go`.
- `fetch-ethereum-bridge-v1@v0.3.0`: `ethereum/contracts/Bridge.sol`,
  `ethereum/scripts/deployment_manifest.json`,
  `fetch/cosmwasm_contract/src/{contract,access_control,state}.rs`.

### 6.3 Tests/PoCs locales ejecutados

| Comando | Resultado |
|---|---|
| `python3 poc/child_probe.py` (1k iters implícito) | store_code OK, instantiate OK, execute OK, gas 17.450.730 |
| `python3 poc/sweep_controls.py` | trigger TRAP a 132k/134k/135k/200k; controles OK |
| `python3 poc/bisect_threshold.py` | primer trap 131018; 1.048.144 B ≈ 1 MiB |
| `python3 poc/bisect_prefix.py` | umbral 131018 para prefijos 4…64 |
| `python3 poc/sweep_variants.py` | `empty`/`replace`/`branch` implícito TRAP; explícito OK |
| `python3 poc/gen_wat7.py` + `child_probe.py` (50 args) | 123 correcto tras 10/100/1.000/10.000 iters de deriva |
| módulo con `f64.sub`/`f64.div` | `store_code(checked=true)` OK (floats permitidos) |

Salidas completas: `poc/logs/RUN-*.txt`, incluida `RUN-10-trap-exact.txt` con el error literal del trigger.

### 6.4 Repos bloqueados

- `CosmWasm/priv_cosmwasm` — privado (404). Acotado por espejo público y binario.
- Repos de IA/docs de la org no auditados por no formar parte del runtime;
  pinneados en el inventario.

### 6.5 Advisories consultados

- `GHSA-v2h8-j899-r676` (crítico, CVSS 10.0, 2026-11-02)
- `GHSA-xmhf-978x-4pcx`, `GHSA-274f-8cvf-h4p9`, `GHSA-37h3-8wp9-3hfx`,
  `GHSA-8v4w-x73c-qp73`, `GHSA-c99m-6ph2-xqm4`, `GHSA-6936-225w-643x`,
  `GHSA-qw47-6x2w-hxh3`, `GHSA-r6j4-873j-3vf7`
- `CWA-2026-006`, `CWA-2026-005`, `CWA-2026-004`

Copias/JSON en `poc/audit/`.
