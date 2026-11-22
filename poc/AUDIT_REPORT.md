# Auditoría de seguridad — fetchd / Singlepass "implicit else"

**Fecha:** 2026-11-21
**Rama:** `arena/e3ba69ce-fetchd` (base `ae12a4fc8886b6bd45f4c70fb4973cd065462ad0`)
**Alcance:** `github.com/fetchai/fetchd` y su pila Wasm (`priv_wasmvm_sec` / `priv_wasmd_sec`)

---

## 1. Resumen ejecutivo

| # | Hallazgo | Estado | Severidad en fetchd |
|---|----------|--------|----------------------|
| 1 | Miscompilación de Singlepass (`if` con parámetro de bloque y `else` implícito) presente en producción | **Confirmado, sin parchear** | **Media** — disparador permissionless y barato (**7 754 gas de SDK**), impacto limitado al aborto de la ejecución; además rompe contratos legítimos |
| 2 | Respuesta vacía del VM (`res.Ok == nil`) en wasmd | **Resuelto** — ya está en upstream v0.61.15 | Ninguna (guardas presentes) |
| 3 | Clasificación errónea de fallos por el harness C ABI | **Corregido** en el PoC | Afectaba a reproducciones previas |
| 4 | Confusión de unidades de gas (puntos de CosmWasm ≠ gas del SDK) en un análisis previo | **Corregido** — ver §2.5 | Invertía la conclusión de alcance |
| 5 | Sonda de integridad con oráculo de valor mal orientado (leía el valor equivocado) | **Corregido** — ver §2.6 | Hacía vacua la conclusión "sin corrupción de valores" |

**Conclusión.** Existe un defecto real de compilación en el motor Singlepass que fetchd ejecuta
en producción y que **no está parcheado en ninguna release de Wasmer**. El disparador es
**permissionless, trivial de construir y muy barato**: ~7 754 gas de SDK (≈0,00004 FET al precio
mínimo local), con **258× de holgura** bajo el `max_gas` de la cadena (2 000 000). El VM lo atrapa
de forma limpia (`call stack exhausted`), la transacción falla y el estado se revierte:
**no hay pérdida de fondos ni parada de cadena**, pero sí se rompe cualquier contrato legítimo
que ejecute más de ~131 000 `if` con `else` implícito.

> **Corrección de una versión anterior de este informe.** Una iteración previa de esta auditoría
> concluyó que el disparador era inalcanzable ("brecha de 543×"). **Era un error de unidades:**
> se compararon *puntos de gas de CosmWasm* con *gas del SDK*. En fetchd los puntos de CosmWasm
> valen 140 000 gas del SDK (`DefaultGasMultiplier`), de modo que el disparador cuesta 7 754 gas
> del SDK, no 1,09 × 10⁹. La conclusión de alcance estaba **exactamente invertida**.

> **Corrección de una segunda versión anterior.** Otra iteración anterior afirmó que el
> defecto "no corrompe valores" apoyándose en 24 parejas implícito/explícito sin discrepancia.
> **Esa sonda estaba mal orientada**: el resultado del bloque `if` queda *encima* de la pila, y
> los `drop` del prefijo se ejecutaban **antes** de capturar el resultado, de modo que la sonda
> medía un valor del prefijo y no el del `if`. Corregida la orientación **y** el desempaquetado
> *signed* de los centinelas (§2.6b), la sonda vuelve a dar **0 desviaciones en 24 pares**, pero
> ahora es un oráculo capaz de detectar una diferencia: la conclusión "sin corrupción de
> valores" queda **demostrada**, no simplemente afirmada.

---

## 2. Hallazgo 1 — Miscompilación de Singlepass (`else` implícito)

### 2.1 Qué es

Wasmer Singlepass no libera el slot de pila que ocupa el parámetro de bloque de un `if`
cuando el bloque **no tiene `else` explícito**. El puntero de pila nativo desciende
**exactamente 8 bytes por cada ejecución del `if` por la rama falsa** y nunca se restaura
hasta el epílogo de la función. Tras **131 028** ejecuciones la pila dedicada de 1 MiB del
JIT toca su página de guarda.

Upstream lo corrigió en:

```
wasmerio/wasmer@e5ca9b93809d744af8b33488a748a284d3d41955
"fix(Singlepass): lower implicit else through existing else handling (#7128)"
Martin Liška, 2026-11-02
```

El fix (diff completo recuperado de la API de GitHub) introduce `emit_if_block_end(was_unreachable)`
y enruta **tanto el `else` explícito como el implícito** por ese mismo cleanup:

```rust
fn emit_if_block_end(&mut self, was_unreachable: bool) -> Result<(), CompileError> {
    // 1. emite los valores de retorno de la rama verdadera
    // 2. drena y libera las locations del tramo superior de la pila de valores
    // 3. reserva de nuevo las locations de los inputs (el else recibe los mismos)
    // 4. salta al final del bloque y materializa label_else
}
```

y en `Operator::End` añade:

```rust
// ControlState::If is reached iff we've got an if with implicit (missing) Operator::Else
if matches!(frame.state, ControlState::If { .. }) {
    self.emit_if_block_end(was_unreachable)?;
    was_unreachable = false;   // la rama falsa implícita siempre es alcanzable
}
```

Test de regresión upstream: `tests/compilers/issues.rs::implicit_else_reclaims_inputs`.

### 2.2 Estado en producción

| Componente | Versión | ¿Parcheado? |
|---|---|---|
| `fetchai/priv_wasmvm_sec` | `v3.0.8-rc.3` (`d89faf180d3fb5de09b4ba59099844cc0a7a2632`) | **No** |
| Wasmer Singlepass | `7.4.2` (release 2026-09-15) | **No** |
| Wasmer upstream | `main` (`e5ca9b9`, 2026-11-02) | Sí, **sin ninguna release que lo contenga** |

```
$ git -C .audit/wasmer tag --contains e5ca9b93809d744af8b33488a748a284d3d41955 | wc -l
0
```

El diff del fork privado de wasmvm frente a upstream `v3.0.8` confirma que **no hay
ningún cambio en el código Rust**: el repositorio solo contiene el crate `libwasmvm`
que *depende* de `cosmwasm-vm` (y por tanto del Wasmer pinado). Cambian únicamente CI,
documentación, `libwasmvm/Cargo.{toml,lock}` (pin a `cosmwasm-*-3.0.10-rc.3` del fork
privado) y los binarios reconstruidos.

```
$ git -C .audit/priv_wasmvm_sec diff --stat upstream-v3.0.8 HEAD
 ... 19 files changed, 414 insertions(+), 172 deletions(-)
   (sin cambios en fuentes Rust; solo Cargo.{toml,lock}, binarios, CI y docs)
```

Observación colateral: el fork privado construye con **Rust 1.82.0** (builders 0103)
mientras que upstream usa **1.95.0** (builders 0104). No afecta a este hallazgo, pero
es una divergencia de toolchain que conviene tener en cuenta en la cadena de suministro.

Artefacto exacto usado en todas las pruebas:

```
.audit/priv_wasmvm_sec/internal/api/libwasmvm.x86_64.so
sha256 0b18713c01c57a12d956614c98de6bd247d29b0649e7fa91a53b9444ce80ac32
identificado como 3.0.8-rc.3
```

### 2.3 Condiciones de disparo (medidas sobre el `.so` de producción)

| Condición | Detalle |
|---|---|
| Tipo de bloque del `if` | ≥1 parámetro (`(param i64) (result i64)`) |
| `else` | **implícito**; con `else` explícito no hay fuga (control) |
| Presión de registros | ≥4 valores extra empujados antes del `if` (prefix 0–3 no fugan, ≥4 sí) → el parámetro debe desbordarse a memoria |
| **Rama tomada** | **solo la rama falsa** (condition=0). Con condition=1 no hay fuga |
| Cuerpo del bucle | debe contener una llamada (toca la pila desalignada) |
| Iteraciones | **131 028** con un `if` por iteración (medido por búsqueda binaria) |

Medida de la fuga (búsqueda binaria del umbral, `trigger_shape.py`):

| `if` por iteración | iteraciones hasta agotar la pila | bytes fugados por iteración |
|---|---|---|
| 1 | **131 028** | 8,0 |
| 2 | **65 514** | 16,0 |
| 4 | **32 757** | 32,0 |
| 8 | **16 379** | 64,0 |

La fuga es **exactamente 8 bytes por ejecución de `if`** y escala linealmente con el número
de `if` por iteración. El control con `else` explícito **nunca** agota la pila.

Matriz upstream completa contra el `.so` de producción (400 000 iteraciones), reproducida
con el test de regresión upstream reconstruido **byte a byte** en Wasm crudo
(`upstream_faithful.py`):

| body | param | prefix | cond | veredicto |
|---|---|---|---|---|
| empty / replace / branch / unreachable / nested-unreachable | 0 | 0,4,31,32 | 0,1 | ok |
| empty / replace / branch / unreachable / nested-unreachable | 1 | 0 | 0,1 | ok |
| empty / replace / branch / unreachable / nested-unreachable | 1 | **4,31,32** | **0 (rama falsa)** | **STACK-EXH** |
| empty / replace / branch / unreachable / nested-unreachable | 1 | **4,31,32** | 1 (rama verdadera) | ok |
| todos | **2** | 0,4,31,32 | 0,1 | **REJECTED** en `store_code` |

Los casos `param=2` los rechaza la comprobación de compatibilidad de CosmWasm v3 en
`store_code` (`check_wasm_functions` → `max_func_results`), por lo que **no son desplegables**.

### 2.4 Mecanismo verificado a nivel nativo

Captura con `sigaltstack`/`SA_ONSTACK` (instalada **después** de crear la VM, para
interceptar la señal cruda antes del handler de Wasmer):

```
si_code = SEGV_ACCERR (2)
si_addr = 0x7f7f4b6fdff8        <- página de guarda ---p [0x7f7f4b6fd000, 0x7f7f4b6fe000)
RSP     = 0x7f7f4b6fe000        <- borde inferior de la región rw-p de 1 MiB
si_addr - RSP = -8              <- un push de 8 bytes justo bajo el límite
RIP     = 0x7f7f4bf30039        <- libwasmvm.x86_64.so + 0x33039
```

Región dedicada del JIT (1 MiB `rw-p` con página de guarda inferior), independiente del
stack del hilo del proceso:

```
7f7cb44fa000-7f7cb44fb000  ---p          <- guard page
7f7cb44fb000-7f7cb45fb000  rw-p 1 MiB   <- pila dedicada de Singlepass
```

El invariante de umbral con `RLIMIT_STACK` (256 KiB … 64 MiB) y con el número de páginas
de memoria Wasm (1–8) confirma que la pila agotada **no** es el stack del hilo.

La pila Wasm la asigna Wasmer (`DEFAULT_STACK_SIZE = 1 MiB`,
`lib/vm/src/trap/traphandlers.rs:53`) sobre un stack de corrutina de **corosensei 0.3.4**
(pin en `libwasmvm/Cargo.lock`). En corosensei la pila se reserva con **una página de guarda
`PROT_NONE` adicional** bajo el área utilizable (`src/stack/unix.rs`), y la comprobación
de recuperabilidad del trap es:

```rust
// Amanieu/corosensei v0.3.4, src/trap.rs:36
pub fn stack_ptr_in_bounds(&self, stack_ptr: usize) -> bool {
    stack_ptr >= self.stack_limit.get() && stack_ptr < self.stack_base.get()
}
```

Wasmer la usa en `lib/vm/src/trap/traphandlers.rs:1020` para decidir si puede recuperar el
trap: si el puntero de pila sigue dentro de los límites de la pila Wasm, Wasmer lo convierte
en la trampa controlada `call stack exhausted`; si ha salido de la pila, no puede y el
proceso muere. **Todas las landings observadas permanecen dentro de la página de guarda**,
por lo que en producción la falla es siempre una trampa limpia (§2.7).

### 2.5 Alcance en fetchd — el disparador SÍ es alcanzable

Coste medido del disparador (forma canónica, prefix 4):

```
1 085 577 315 puntos de CosmWasm = 7 754 gas de SDK
```

Techo real por transacción en fetchd:

```
consensus_params.block.max_gas = 1 500 000   (fetchhub-1, fetchhub-2)
                                = 2 000 000   (fetchhub-3, fetchhub-4 — actual)
```

Y `baseapp` solo incluye una tx en una propuesta si su límite de gas cabe en el bloque:

```go
// .audit/cosmos-sdk/baseapp/abci_utils.go  (defaultTxSelector.SelectTxForProposal)
if (txGasLimit + ts.totalTxGas) <= maxBlockGas {
        ts.totalTxGas += txGasLimit
        ts.selectedTxs = append(ts.selectedTxs, txBz)
}
```

**Las dos magnitudes hay que compararlas en la misma unidad.** El presupuesto de la cadena
está en *gas del SDK*; el VM mide en *puntos de gas de CosmWasm*, y la conversión es:

```go
// wasmd/x/wasm/types/gas_register.go
DefaultGasMultiplier = 140_000   // cuántos puntos de CosmWasm = 1 gas de SDK
ToWasmVMGas(sdk)   = sdk * 140_000
FromWasmVMGas(vm)  = vm  / 140_000
```

Por tanto el presupuesto real de una tx es **2 000 000 × 140 000 = 280 000 000 000 puntos**,
y a 8 280 puntos por iteración (prefix 4):

```
iteraciones asequibles = 280 000 000 000 / 8 280 = 33 816 000
iteraciones necesarias = 131 028
margen                 = 258x
```

Comprobación experimental directa con el límite real (`gas_units.py`):

| límite de gas | gas consumido | resultado |
|---|---|---|
| 2 000 000 SDK gas (280 000 000 000 puntos) | 1 085 577 315 | **STACK EXHAUSTED — miscompilación disparada** |
| 1 085 577 314 puntos | — | sin disparo (búsqueda binaria del mínimo) |

Coste real de la transacción atacante: **7 754 gas de SDK** (≈0,000039 FET al precio mínimo
de 5 atestfet/gas). **El disparador es alcanzable y permissionless.**

> Esta sección **sustituye** a la versión anterior del informe, que afirmaba un déficit de
> 543×. Ese número provenía de dividir gas del SDK entre puntos de VM — la misma confusión
> de unidades. La conclusión correcta es la inversa: **holgura de 258×**.

### 2.6 Integridad: los valores calculados son CORRECTOS

La pregunta de si el defecto permite **robar fondos** (es decir, si produce valores erróneos
que un contrato pueda observar) se responde con dos oráculos independientes, ambos sobre el
`.so` de producción:

**(a) Oráculo dentro del guest (idéntico al de upstream).** El test upstream comprueba cada
resultado del bloque contra el valor esperado con `i64.ne` + `unreachable`. Recorriendo el
número de iteraciones a través del umbral de agotamiento:

| iteraciones | veredicto | gas |
|---|---|---|
| 1 | ok | 928 265 |
| 100 | ok | 1 918 760 |
| 1 000 | ok | 10 923 260 |
| 100 000 | ok | 1 001 418 260 |
| 131 000 | ok | 1 311 573 260 |
| **131 028** | **STACK-EXH** | 1 311 593 830 |

Si el valor fuera incorrecto, el oráculo `unreachable` dispararía en la **primera** iteración
(gas ≈700 000). No ocurre: la ejecución es **correcta durante 131 000 iteraciones** y solo
falla cuando la pila se agota. El fallo es de disponibilidad, no de integridad.

**(b) Oráculo diferencial (implícito vs. explícito).** `integrity_probe.py` construye el mismo
módulo dos veces — con `else` implícito y con `else` explícito que reenvía el parámetro, que es
justo lo que la especificación de WebAssembly exige del `else` implícito — y lee de vuelta el
valor producido por el `if` y cuatro centinelas que viven en la pila nativa:

| iteraciones | condición | valor implícito | valor explícito | centinelas | diferencia |
|---|---|---|---|---|---|
| 1 … 100 000 | 0 (rama falsa) | `0x123456789abcdef` | `0x123456789abcdef` | `0xaaaaaaaaaaaaaaaa` | **ninguna** |
| 1 … 100 000 | 1 (rama verdadera) | `0x3e7` | `0x3e7` | `0xaaaaaaaaaaaaaaaa` | **ninguna** |

Los valores coinciden con lo que exige la especificación (`0x123456789abcdef` = el parámetro
reenviado por la rama falsa; `0x3e7` = el valor de la rama verdadera) y **los centinelas de la
pila nativa no se corrompen**.

`semantic_probe.py`, reparado como se describe abajo, recorre además prefix ∈ {0,1,3,4,8,16} ×
condición ∈ {0,1} × encadenado ∈ {sí,no} = **24 pares, 0 desviaciones**, con los centinelas
intactos en todos ellos.

> **Corrección de una sonda anterior.** `semantic_probe.py` afirmaba Teóricamente una copia
> condición→parámetro, y sus 24 parejas "sin discrepancia" se tomaban como prueba de que no hay
> corrupción. **La sonda tenía dos defectos**: (i) el resultado del `if` queda encima de la pila
> de valores y los `drop` del prefijo se ejecutaban antes de capturarlo, de modo que se medía un
> valor del prefijo y no el del `if`; (ii) los centinelas se desempaquetaban como *signed*, y su
> suma correcta (0xAAAAAAAAAAAAAAAA) tiene el bit alto activo, por lo que toda celda parecía
> desviada. Corregidas ambas cosas, la sonda da **0 desviaciones en 24 pares** — y, a diferencia
> de antes, es un oráculo **capaz** de detectar una diferencia.

**Conclusión de integridad: no hay vía probada de robo de fondos por este defecto.** El
impacto es de disponibilidad: la transacción falla de forma determinista y el estado se revierte.

### 2.7 El fallo es una trampa limpia, no la muerte del proceso

En el Wasmer de producción el fallo se traduce siempre en la trampa controlada:

```
RuntimeError: call stack exhausted
```

- Wasmer convierte el `SIGSEGV` de la página de guarda en esa trampa, **siempre que el puntero
  de pila siga dentro de los límites de la pila Wasm** (`stack_ptr_in_bounds`, §2.4). Todas las
  landings medidas caen dentro de la página de guarda, luego la recuperación es siempre posible.
- La API C devuelve **vector de respuesta presente pero vacío** + vector de error con texto.
- El binding Go devuelve el error → wasmd devuelve un error determinista → la tx falla y el
  estado se revierte.

La matriz de muerte de proceso (`crash_test.py`, 600–4096 `if` por iteración, llamadas dentro
y después del bucle, variantes sin llamada y llamadas a host; `kill_sweep.py`, 72 variantes)
**no encontró ninguna muerte de proceso** por `SIGSEGV`/`SIGABRT`: todas las variantes con
llamada fallaron limpiamente con errores de Wasmer y las variantes sin llamada devolvieron `OK`.
No se ha probado una forma válida que salte completamente la página de guarda.

### 2.8 Impacto

**Sobre la cadena:** ninguno. La transacción atacante falla de forma determinista, se revierte
el estado y el nodo sigue vivo. No hay parada de cadena.

**Sobre otros contratos:** **este es el impacto real**. El defecto no discrimina por quién
llama: cualquier contrato legítimo que ejecute más de ~131 000 `if` con `else` implícito y
parámetro de bloque (con suficiente presión de registros) **falla**, aunque su lógica sea
correcta. Es un fallo de disponibilidad *de terceros*, determinista y reproducible.

**Sobre el atacante:** puede provocar el fallo en su propia tx por ~7 754 gas de SDK. No
obtiene robo de fondos, no obtiene muerte de nodo y no gana nada; el valor del disparador es
puramente demonstrativo (y como *denegación de servicio dirigida*, el atacante tendría que
ejecutar el contrato víctima, lo que también ejecuta su propia lógica — el vector real es el
fallo de contratos legítimos described above).

### 2.9 Recomendación

1. **Backport del fix upstream** `e5ca9b938` a la rama de Singlepass 7.4.2 usada por
   `priv_wasmvm_sec`, o migrar a una release de Wasmer que lo contenga cuando exista.
   Es una modificación de ~131 líneas en `lib/compiler-singlepass/src/codegen.rs`.
2. **Auditar contratos legítimos** desplegados en fetchhub que usen `if` con parámetro de
   bloque y `else` implícito en bucles largos: son las víctimas reales del defecto.
3. Alternativa de mitigación inmediata (si se quiere defensa en profundidad): hacer que el
   frame de la función se restaure también en el `End` de un `if` sin `else` — que es
   precisamente lo que hace el fix upstream.

---

## 3. Hallazgo 2 — `res.Ok == nil` en wasmd: ya resuelto

El fork `fetchai/priv_wasmd_sec` (`v0.61.15-rc.3`, commit de producción
`ab17af8e72692541e5eb1b57c2d5480ed8084300`) contiene hotfixes con nombres reveladores
(`fix ok nil`, `fix burn`). Comparado con upstream `wasmd v0.61.15`, **el código Go es
idéntico**: el diff solo toca CI y documentación.

```bash
$ git -C .audit/priv_wasmd_sec diff --stat upstream-v0.61.15 HEAD
 .github/…  CHANGELOG.md  Dockerfile  README.md  go.mod  go.sum
```

Las guardas `res.Ok == nil` ya están en upstream y por tanto en producción:

```
x/wasm/keeper/keeper.go:367   instantiate
x/wasm/keeper/keeper.go:459   execute
x/wasm/keeper/keeper.go:669   sudo
x/wasm/keeper/keeper.go:715   reply
x/wasm/keeper/relay.go:199    OnRecvPacket
x/wasm/keeper/relay.go:397    handleIBCBasicContractResponse (cubre IBC e IBC2)
x/wasm/keeper/ibc2.go:230     OnRecvIBC2Packet
```

Observación menor (no explotable): `x/wasm/keeper/keeper.go:627` (`migrate`) devuelve
`res.Ok` sin comprobar nil; como no se desreferencia, el resultado es un `data` vacío
sin error. Sin impacto.

---

## 4. Hallazgo 3 — Trampa en el harness (corregida)

La API C de CosmWasm puede devolver **un vector de respuesta presente pero vacío junto con
un vector de error con texto**. Clasificar el resultado solo con `res.is_none` convierte
el fallo en un falso "éxito".

Consecuencia práctica: la primera ejecución de la matriz upstream (120 casos) dio "80/80
ok" y llevó a la conclusión errónea de que la forma upstream no disparaba el fallo. Tras
corregir el harness (`run_poc.run_once` registra el vector de error **incondicionalmente**),
la matriz da 24 `STACK-EXH` + 8 `TRAP` + 48 `ok` + 40 `REJECTED`.

Este detalle importa para cualquier reproducción futura: el "éxito" con respuesta vacía
es exactamente el modo `res.Ok == nil` que el fork de wasmd tuvo que parchear.

---

## 5. Reproducción

Todos los scripts usan el `.so` de producción real vía `ctypes` (no hay toolchain Rust/Go
en el entorno).

```bash
cd poc

# test de regresión upstream reconstruido byte a byte + matriz completa
python3 upstream_faithful.py --matrix --iters 400000

# frontera entre corrupción de valor y agotamiento de pila
python3 upstream_faithful.py --boundary

# integridad: implícito vs explícito (oráculo diferencial de valores)
python3 integrity_probe.py

# forma exacta del disparador: dependencia de datos, umbral y bytes por if
python3 trigger_shape.py

# alcance frente al techo de gas de la cadena (unidades correctas)
python3 reachability.py

# experimento decisivo con el límite de gas real
python3 gas_units.py

# matriz histórica y economía
python3 upstream_matrix.py matrix --iters 400000
python3 gas_economics.py
```

Artefactos clones en `.audit/` (excluido de Git por `.git/info/exclude`):
`priv_wasmvm_sec` (`v3.0.8-rc.3`), `priv_wasmd_sec` (`ab17af8e`), `wasmer`,
`wasmd` (`v0.61.15`), `wasmvm` (`v3.0.8`), `cosmwasm` (`v3.0.10-rc.3`),
`cosmos-sdk`, `genesis-fetchhub`, `cw-fetch-std`, `FIPs`, `advisories`.

Fuentes de referencia obtenidas para esta auditoría:

| Fuente | Qué aportó |
|---|---|
| `wasmerio/wasmer@e5ca9b938` (API GitHub) | Diff completo del fix (`emit_if_block_end`) y test de regresión |
| `Amanieu/corosensei` tag `v0.3.4` (sha `4b5db48`) | Implementación de `stack_ptr_in_bounds` y de la página de guarda |
| `wasmer/lib/vm/src/trap/traphandlers.rs` (v7.4.2 local) | `DEFAULT_STACK_SIZE` = 1 MiB, política de recuperación del trap |

---

## 6. Limitaciones de esta auditoría

* No se ha construido un nodo fetchd completo ni se ha reproducido el fallo a nivel de
  cadena; todas las conclusiones de alcance se derivan del código del SDK
  (`abci_utils.go`, `consensus_params`) y de los genesis de fetchhub, más la medición
  directa del gas en el `.so` de producción.
* El `minimum-gas-prices` real de la red principal no es público en los artefactos
  consultados; no afecta a la conclusión (el techo relevante es `max_gas`, no el precio).
* No se ha construido el compilador Singlepass parcheado, de modo que no se ha ejecutado el
  test de regresión upstream contra un Wasmer corregido; la conclusión de que el fix upstream
  resuelve el problema se apoya en el diff y en el comentario del propio test upstream, no en
  una ejecución local del caso corregido.
* No se ha probado una forma válida que salte completamente la página de guarda de 4 KiB; el
  intento existente (`guard_skip.py`) genera Wasm con tipos inválidos y es rechazado por el
  validador, por lo que no aporta evidencia. La ausencia de muertes de proceso está medida, no
  provenida.
* No se ha auditado el resto de la superficie de `fetchd` (módulos custom, IBC2,
  ICA, tokenfactory) en esta iteración.
* El advisory `GHSA-v2h8-j899-r676` sigue sin corroboración pública (404 en la API de
  GitHub) y **no debe citarse como confirmado**.
