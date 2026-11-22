# Auditoría de seguridad — fetchd / Singlepass "implicit else"

**Fecha:** 2026-11-21
**Rama:** `arena/e3ba69ce-fetchd` (base `ae12a4fc8886b6bd45f4c70fb4973cd065462ad0`)
**Alcance:** `github.com/fetchai/fetchd` y su pila Wasm (`priv_wasmvm_sec` / `priv_wasmd_sec`)

---

## 1. Resumen ejecutivo

| # | Hallazgo | Estado | Severidad en fetchd |
|---|----------|--------|----------------------|
| 1a | Miscompilación de Singlepass (`if` con parámetro de bloque y `else` implícito) presente en producción | **Confirmado, sin parchear** | **Media** — disparador permissionless y barato (**7 754 gas de SDK**); rompe contratos legítimos |
| 1b | **Escalada de la misma fuga a muerte del proceso del validador** (`SIGSEGV` irrecuperable) | **Confirmado, sin parchear** | **Alta** — disparador permissionless de **4 652 gas de SDK** (430× de holgura) que **mata el proceso** del nodo |
| 1c | **La rama falsa del `else` implícito se salta la canonicalización de NaN** → resultado flotante dependiente de la CPU y **ramificación divergente** | **Confirmado, sin parchear** | **Media/Alta** — riesgo de **divergencia de app hash** entre arquitecturas y al aplicar el parche |
| 2 | Respuesta vacía del VM (`res.Ok == nil`) en wasmd | **Resuelto** — ya está en upstream v0.61.15 | Ninguna (guardas presentes) |
| 3 | Clasificación errónea de fallos por el harness C ABI | **Corregido** en el PoC | Afectaba a reproducciones previas |
| 4 | Confusión de unidades de gas (puntos de CosmWasm ≠ gas del SDK) en un análisis previo | **Corregido** — ver §2.5 | Invertía la conclusión de alcance |
| 5 | Sonda de integridad con oráculo de valor mal orientado (leía el valor equivocado) | **Corregido** — ver §2.6 | Hacía vacua la conclusión "sin corrupción de valores" |

**Conclusión.** Existe un defecto real de compilación en el motor Singlepass que fetchd ejecuta
en producción y que **no está parcheado en ninguna release de Wasmer**. El disparador es
**permissionless, trivial de construir y muy barato**.

La cadena completa esta verificada en **§2.10**: fetchd fija `priv_wasmvm_sec v3.0.8-rc.3`
(commit `d89faf18`) -> `cosmwasm-vm 3.0.10-rc.3` -> `wasmer 7.4.2`, donde **Singlepass es el
único compilador presente** (`make_compiler_config()` -> `wasmer::sys::Singlepass::new()`, y el
lockfile no contiene Cranelift ni LLVM). Por tanto **no hay mitigación por cambio de
compilador**, y la canonicalización de NaN está **activa por defecto** en el binario que el nodo
carga. Los limites de validacion se quedan en sus defaults (`max_function_results = 1`), lo que
acota la superficie a `if (param T)(result T)`, y `CodeUploadAccess = AllowEverybody` hace que
**cualquier cuenta** pueda llegar al disparador.

- **Como trampa limpia** (~7 754 gas de SDK, 258× de holgura): el VM aborta la ejecución con
  `call stack exhausted`, la transacción falla y el estado se revierte. No hay pérdida de fondos,
  pero **rompe cualquier contrato legítimo** que ejecute más de ~131 000 `if` con `else`
  implícito.
- **Como muerte del proceso** (~4 652 gas de SDK, 430× de holgura — ver **§2.8**): la misma fuga
  puede escalarse hasta que el `SIGSEGV` sea **irrecuperable**, y el **proceso del validador
  muere con `SIGSEGV`**. Es una denegación de servicio contra el nodo, no una transacción
  fallida.
- **Como no determinismo de coma flotante** (ver **§2.9.2**): la rama falsa del `else` implícito
  **se salta la canonicalización de NaN**, de modo que un `f64` NaN conserva el *payload del
  hardware* (0xFFF8… en x86-64, 0x7FF8… en AArch64) en lugar del patrón canónico. Consecuencia
  práctica: **el mismo programa da distinto resultado según cómo el compilador emitiera el
  `if`**, y una red con validadores de arquitecturas distintas puede obtener **app hashes
  distintos**. Además, **aplicar el fix upstream cambia el resultado** de esos contratos, así que
  el backport no es semánticamente neutro.

> **Corrección de una versión anterior de este informe.** Una iteración previa de esta auditoría
> concluyó que el disparador era inalcanzable ("brecha de 543×"). **Era un error de unidades:**
> se compararon *puntos de gas de CosmWasm* con *gas del SDK*. En fetchd los puntos de CosmWasm
> valen 140 000 gas del SDK (`DefaultGasMultiplier`), de modo que el disparador cuesta 7 754 gas
> del SDK, no 1,09 × 10⁹. La conclusión de alcance estaba **exactamente invertida**.

> **Corrección de una tercera versión anterior (importante).** Una iteración anterior afirmaba
> que el fallo *"es una trampa limpia, no la muerte del proceso"*. **Esa afirmación era falsa**:
> faltaba una forma de escalado (§2.8) en la que el `SIGSEGV` ocurre con el puntero de pila
> **por debajo** del límite de la pila Wasm, que es exactamente la condición que hace que el
> manejador de trampas de Wasmer decline recuperar el fallo. La matriz de muerte de proceso
> anterior (`kill_sweep.py`, 72 variantes) no lo detectó porque **todas** sus variantes con
> llamada la tenían **dentro** del bucle, donde el primer `push` cae en la página de guarda y sí
> es recuperable.

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
proceso muere. En las formas medidas hasta aquí **todas las landings observadas permanecen
dentro de la página de guarda**, por lo que la falla es una trampa limpia (§2.7). **§2.8
documenta una forma que consigue que la landing caiga por debajo de la página de guarda** (con
`SP < limit`), que es exactamente la condición de irrecuperabilidad.

#### 2.4.1 Differential CFG-aware completo (JIT real de producción)

Los dos módulos (implícito y explícito) producen JIT distintos; el difference se ve en el
**control de flujo**, no en los valores. Checksums: implícito
`fabc44e53ab9d96e9aaa1fc0e50f742c40c362b71e389ad29d8b69b36ee9fd3e`, explícito
`221573d50fe190e4ae791293b4ca2e9b93795152c599e48a688ee04212e84a03`.

| | **implícito** | **explícito** |
|---|---|---|
| test de la condición | `0x478  je 0x574` | `0x478  je 0x579` |
| `0x574` | `sub $0x8,%rsp` — **es la etiqueta de FIN del bloque** | `jmp 0x66f` — el then-arm salta a la etiqueta de FIN |
| `0x579` | *(no existe: aquí está la etiqueta de FIN)* | `sub $0x8,%rsp` — **el brazo `else`**, con su propio `add $0x8,%rsp` en `0x590` |
| cleanup `add $0x8,%rsp` en `0x56d` | lo ejecuta **sólo** el then-arm | lo ejecuta **sólo** el then-arm |
| ruta de la condición falsa | salta a `0x574` **saltándose el `add $0x8,%rsp` de `0x56d`** | entra en `0x579`, región con su propio par `sub`/`add` balanceado |

Es decir: **en la versión rota, la rama falsa salta directamente a la etiqueta de fin y se
salta el `add $0x8,%rsp` que libera el slot del bloque** → 8 bytes de pila nativa fugados por
cada ejecución de la rama falsa. En la versión corregida, la rama falsa entra en una región
(`else`) con su propio par `sub`/`add` y el then-arm ejecuta el cleanup: **la pila queda
balanceada en ambas ramas**.

Esto corresponde exactamente al diff del fix upstream: el `Operator::End` roto emite
`emit_label(frame.label)` **antes** de `emit_label(label_else)`, de modo que la ruta que salta
a `label_else` se salta el `release_locations()` (el `add rsp, N`); el fix introduce
`emit_if_block_end()`, que emite `jmp_unconditional(frame.label)` **antes** de
`emit_label(label_else)`, dejando el brazo `else` como una región separada y balanceada.

> **Consecuencia para la escalada (§2.8).** La fuga es *exactamente* este `add $0x8,%rsp`
> omitido: 8 bytes por iteración, como miden las direcciones de fallo. Y como la omisión
> ocurre **en el bloque**, la fuga se repite en cada iteración de un bucle, mientras que la
> operación que la compensa (`add $0x8,%rsp`) está en el camino del `then`.

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

### 2.7 La forma habitual es una trampa limpia

En el Wasmer de producción el fallo *más común* se traduce en la trampa controlada:

```
RuntimeError: call stack exhausted
```

- Wasmer convierte el `SIGSEGV` de la página de guarda en esa trampa, **siempre que el puntero
  de pila siga dentro de los límites de la pila Wasm** (`stack_ptr_in_bounds`, §2.4). Todas las
  landings medidas caen dentro de la página de guarda, luego la recuperación es posible.
- La API C devuelve **vector de respuesta presente pero vacío** + vector de error con texto.
- El binding Go devuelve el error → wasmd devuelve un error determinista → la tx falla y el
  estado se revierte.

> **Importante: esta NO es la única forma.** La matriz de muerte de proceso anterior
> (`crash_test.py`, `kill_sweep.py`, 72 variantes) **no encontró ninguna muerte de proceso**, pero
> todas sus variantes con llamada la tenían **dentro** del bucle. En esa geometría el primer
> `push` cae en la página de guarda, con `SP >= limit`, y por tanto **sí** es recuperable.
> La forma de §2.8 mueve la llamada **fuera** del bucle y **sí** mata el proceso.

### 2.8 Escalada: de la trampa limpia a la muerte del proceso del nodo

#### 2.8.1 La geometría de la pila

La pila Wasm no es la pila nativa del hilo: la gestiona **corosensei 0.3.4**
(`src/stack/unix.rs`, `DefaultStack::new`):

```rust
let mmap_len = size.checked_add(page_size + page_size - 1).unwrap() & !(page_size - 1);
let mmap = mmap(PROT_NONE, mmap_len);
mprotect(mmap + page_size, size, READ | WRITE);   // todo menos la página de guarda
base  = mmap + mmap_len;                          // tope
limit = mmap;                                     // fondo de la página de guarda
```

Para `size = 1 MiB` (el `DEFAULT_STACK_SIZE` de Wasmer, `traphandlers.rs:57`) queda:

| region | rango | proteccion |
|---|---|---|
| pila usable | `[limit + 4096, base)` | RW |
| **pagina de guarda inferior** | `[limit, limit + 4096)` | `PROT_NONE` |
| pagina de guarda superior | `[base - 4096, base)` | `PROT_NONE` |

Y el criterio de recuperabilidad de Wasmer (`lib/vm/src/trap/traphandlers.rs:1020`):

```rust
if !self.coro_trap_handler.stack_ptr_in_bounds(sp) { return false; }   // sp = RSP en el fallo
```

con `stack_ptr_in_bounds(p) = p >= limit && p < base` (`corosensei/src/trap.rs:37`).

**La condicion de muerte es, por tanto, precisa: el fallo debe ocurrir con `RSP < limit`.**

#### 2.8.2 La forma que la cumple

```wat
(func (export "execute") (param i32 i32 i32) (result i32)
  (local $i i32)
  (local.set $i (i32.const N))          ;; N ~ 131 539
  (loop
    ;; presion de registros: 4 x local.get $x  (obliga a volcar el parametro de bloque)
    local.get $x   ;; x4
    local.get $x   ;; <- el parametro del bloque `if`
    i32.const 0    ;; <- la CONDICION es falsa
    if (param i64) (result i64)         ;; <- `else` IMPLICITO
    end
    drop x5
    local.get $i  i32.const 1  i32.sub  local.tee $i  br_if 0
  )
  call $callee                          ;; <- el `push` que dispara el fallo
  (i32.const 1))
```

El bucle **no contiene ninguna llamada**. Eso es lo que permite la escalada:

- `sub rsp, N` (la extension de la pila por el slot filtrado) es una operacion **pura de
  registro**: no toca memoria.
- Los slots de la pila de valores se direccionan **relativos a RBP** (`Location::Memory(RBP,
  -offset)`), no a RSP: siguen siendo accesibles aunque RSP se hunda.
- Por tanto el bucle puede **derivar RSP por debajo de la pagina de guarda sin tocarla
  jamas**: 8 bytes por iteracion (medido: la direccion de fallo baja exactamente 8 bytes por
  iteracion).
- La `call` posterior empuja la direccion de retorno en `RSP-8`, que ya esta **por debajo de
  `limit`** → `SIGSEGV` con `SP < limit` → `handle_trap` devuelve `false` → el manejador de
  senales **restaura `SIG_DFL` y vuelve** → la instruccion que fallo **se re-ejecuta** → el
  proceso **muere con `SIGSEGV`**.

#### 2.8.3 Mediciones (`.so` de produccion, SHA256 `0b18713c…`)

| iteraciones | resultado |
|---|---|
| ≤ 130 000 | `OK` — el bucle deriva la pila sin tocar la pagina de guarda |
| 131 538 | `RuntimeError: call stack exhausted` — trampa **recuperable** |
| **131 539** | **`SIGSEGV` — el proceso muere** |

En la frontera:

```
131538  SIGSEGV addr=0x7f48d0cfcff8  rsp=0x7f48d0cfcff8   (SP >= limit  -> recuperable)
131539  SIGSEGV addr=0x7f48d0cfcff0  rsp=0x7f48d0cfcff8   (SP <  limit -> IRRECUPERABLE)
```

- `addr == RSP - 8` en **todos** los casos: el fallo es el `push` de la direccion de retorno.
- La direccion de fallo baja **exactamente 8 bytes por iteracion**: la tasa de la fuga.
- El `RIP` es constante y cae en el mapeo JIT anonimo (`r-xp`), en el offset **0x54d** del
  codigo JIT de este modulo:

```asm
0x543    sub    $0x8,%rsp        ; <- la extension del slot filtrado (la fuga)
0x54a    mov    %r15,%rdi
0x54d    call   0x552            ; <- INSTRUCCION QUE FALLA (RIP del SIGSEGV)
0x552    add    $0x8,%rsp
```

#### 2.8.4 Controles

| control | resultado |
|---|---|
| **Modulo identico con `else` explicito** (misma forma, mismo bucle, 200 000 iteraciones) | `OK` — sin fuga, sin trampa, sin muerte |
| Modulo implicito, 130 000 iteraciones | `OK` |
| Modulo implicito, `prefix = 0, 1, 2, 3` (el parametro de bloque **no** se vuelca a la pila nativa) | `OK` incluso con 2 097 152 iteraciones — **no hay fuga** |

La condicion "el parametro de bloque debe estar en la pila nativa" (presion de registros) es
justa: es lo que hace que el `if` reserve un *slot* de pila que la ruta falsa no libera. Es
 tambien la razon por la que el test de regresion upstream usa `prefix_count` ∈ {0, 4, 31, 32}.

#### 2.8.5 Coste y alcance

- **Coste:** 651 378 615 puntos de gas de la VM = **4 652 gas de SDK**, con **430x de holgura**
  bajo el `max_gas` de la cadena (2 000 000). Es *mas barato* que la forma de trampa limpia
  porque el bucle es mas pequeno.
- **Permisionless:** cualquier contrato puede ejecutar esta forma; no requiere ningun privilegio.
- **Efecto:** el **proceso del validador** (`wasmd`) muere con `SIGSEGV`. El estado de la
  cadena no se corrompe (la transaccion ni siquiera se aplica), pero el nodo cae y debe
  reiniciarse. Repetible por cualquier transaccion crafted.
- **Por que muere el nodo y no solo la transaccion:** `libwasmvm` se carga por `cgo`; un
  `SIGSEGV` dentro de la libreria C no es recuperable por el runtime de Go (que aborta el
  proceso con "unexpected fault address"), y en cualquier caso el propio Wasmer ya ha
  restaurado `SIG_DFL` y re-ejecutado la instruccion que fallo. Lo observado aqui es el
  `SIGSEGV` del proceso que carga la libreria — el mismo mecanismo por el que moriria el
  validador.

> **Lo que NO es.** Esto **no** es ejecucion arbitraria de codigo, ni robo de fondos, ni
> corrupcion de memoria del estado de la cadena: es una **denegacion de servicio que mata el
> proceso**. La investigacion de una via de exfiltracion o de manipulacion del flujo de control
> sigue **abierta** y se documenta por separado en §2.9 y §5.

### 2.9 Integridad: el alcance exacto de la afirmacion

*(§2.6 demuestra, con oraculo diferencial, que los valores calculados por la forma cubierta son
correctos. Esta seccion delimita **que** queda demostrado y **que** no.)*

#### 2.9.1 Por que la fuga no altera los valores — y por que eso no basta

En el compilador vulnerable, el `Operator::If` copia los parametros del bloque a los slots de
retorno **antes** de la rama (`emit_relaxed_mov`), y el fix upstream la traslada al brazo
`else`. Ambas rutas dejan **los mismos valores** en los mismos sitios: la copia es
semanticamente neutra (los slots se permutan entre si, sin cruzar datos de tipo). Por eso:

- La pila de valores del compilador queda con **una entrada de mas**, no con valores cambiados.
- Los slots de la pila de valores se direccionan **relativos a RBP**, asi que la deriva de RSP
  no puede corromperlos.

**Esto es evidencia directa y no una hipotesis**: `integrity_probe.py` y `semantic_probe.py` dan
**0 desviaciones en 24 pares** implicito/explicito, y el test de regresion upstream
`implicit_else_reclaims_inputs` afirma lo mismo para las formas que cubre.

> **Correccion de una afirmacion anterior de este informe.** Una version previa de §2.9
> afirmaba que *"la canonicalizacion de NaN no cambia nada aqui"* porque los valores del bloque
> llevaban `CanonicalizeType::None`. **Es falso**: `CanonicalizeType::None` solo lo llevan los
> valores que *no* son float (o los `f64.const`); un `f64` producido por una operacion
> aritmetica lleva la marca `F64`, y la canonicalizacion se difiere hasta la salida de la
> funcion. Como la rama falsa del `else` implicito **no pasa por `emit_return_values()`**, la
> canonicalizacion **se pierde**. Ver §2.9.2: es un segundo defecto, de naturaleza distinta
> (no determinismo), y el mismo fix upstream lo corrige.

#### 2.9.2 La canonicalizacion de NaN se pierde en la rama falsa del `else` implicito

Singlepass activa la canonicalizacion de NaN **por defecto**
(`lib/compiler-singlepass/src/config.rs:102` → `enable_nan_canonicalization: true`), a diferencia
de Cranelift y LLVM, donde esta desactivada. El motivo es **critico para el consenso**: el NaN
canonico (`0x7FF8_0000_0000_0000` para f64, `machine_x64.rs::canonicalize_nan`) hace que el
resultado de una operacion de coma flotante sea **identico bit a bit en todas las CPUs**, de modo
que los validadores coincidan en el app hash.

La canonicalizacion es **diferida**: `f64.add`, `f64.sub`, `f64.mul`, `f64.div`, `f64.sqrt`,
`f64.floor`, `f64.ceil`, `f64.trunc` y `f64.nearest` empujan su resultado con la marca
`CanonicalizeType::F64` pero **no lo canonicalizan en el sitio**
(`codegen.rs:1899-1990`); se canonicaliza despues, al salir de la funcion, en
`emit_return_values()`.

El fix upstream cambia justo ahi:

| | `else` **implicito** (vulnerable) | `else` **explicito** (corregido) |
|---|---|---|
| rama verdadera | pasa por `emit_return_values()` → canonicaliza | idem |
| **rama falsa** | **copia cruda** (`emit_relaxed_mov`), **sin canonicalizar** | pasa por `emit_if_block_end()` → `emit_return_values()` → **canonicaliza** |

**Medido sobre el `.so` de produccion** (`nan_canon_probe.py`), con `f64.sqrt(-1.0)` pasado como
parametro de bloque y la condicion en `false`:

```
productor  cond  implicito                          explicito                         juicio
sqrt       0     0xfff8000000000000 (NaN x86)       0x7ff8000000000000 (canonico)     *** DIFIERE ***
sqrt       1     0x7ff8000000000000 (canonico)       0x7ff8000000000000 (canonico)     ok
```

Y la diferencia se traduce en una **ramificacion divergente** (el contrato comprueba los bits del
float y escribe un estado distinto):

```
productor  cond  implicito  explicito  juicio
sqrt       0     1          2          *** RAMIFICACION DIVERGENTE ***
```

**Confirmacion a nivel JIT** (las secuencias de canonicalizacion son
`vcmpunordsd` + `vblendvpd`):

| variante | secuencias de canonicalizacion en el JIT |
|---|---|
| `else` implicito | **1** (solo la rama verdadera, offset `0x1a4`) |
| `else` explicito | **2** (`0x1a4` y `0x270`, una por rama) |

**Consecuencias**

1. **No determinismo entrearchitecturas.** El NaN crudo depende de la CPU: x86-64 produce
   `0xFFF8_0000_0000_0000` (el "real indefinite") y AArch64 produce
   `0x7FF8_0000_0000_0000`. El `else` implicito deja pasar el valor crudo; el explicito lo
   canonicaliza. Una red con validadores de arquitecturas distintas (el `.so` de produccion
   incluye `libwasmvm.aarch64.so`) **puede obtener app hashes distintos para el mismo bloque**.
   Es exactamente el problema que la canonicalizacion existe para evitar.
2. **El mismo programa fuente da distinto resultado** segun el compilador haya emitido `if`/`else`
   o solo `if`: el compilador de Rust/LLVM decide esa forma, no el contrato.
3. **El parche upstream cambia el comportamiento observable** de los contratos afectados
   (`0xFFF8…` → `0x7FF8…`): para un contrato que ramifica sobre los bits del float, el app hash
   cambia al actualizar Wasmer. **El backport del fix no es semanticamente neutro** y hay que
   auditar los contratos de coma flotante antes de aplicarlo.

**Lo que NO es:** no hay robo de fondos ni corrupcion de la cadena por esta via. Un NaN no se
puede serializar en JSON (serde_json lo rechaza), asi que el valor no puede almacenarse en el
estado; lo observable es la *ramificacion* y, con ella, el estado que el contrato decide
escribir. El vector es de **divergencia de estado/app hash**, no de robo.

**Estado de la evidencia:** *directa* para el comportamiento medido (bits y ramificacion) y
*directa* para la diferencia de JIT. Que el **fix upstream lo corrija** se deduce del diff
(`emit_if_block_end` → `emit_return_values` → `canonicalize_nan`): **no** se ha compilado el
Singlepass parcheado en este entorno, igual que para el resto del informe.

#### 2.9.3 Matriz de formas: la semántica de valores es correcta

El test de regresion upstream solo cubre bloques `(param i64)(result i64)` y su caso *"branch"*
usa `br 0` con el parametro del bloque en la pila, de modo que el valor esperado **coincide**
con el parametro: ese caso no puede distinguir una compilacion correcta de una incorrecta**.
`shape_matrix.py` cubre las formas que faltan, comparando cada una contra su gemelo `else`
explicito (semanticamente equivalente por construccion) y contra el valor que exige la
especificacion:

| forma | `else` implicito | `else` explicito | esperado (spec) | juicio |
|---|---|---|---|---|
| `passthrough` (el resultado es el parametro) | `0123456789abcdef` | `0123456789abcdef` | `0123456789abcdef` | ok |
| `replace` (el then-arm reemplaza el parametro) | `0123456789abcdef` | `0123456789abcdef` | `0123456789abcdef` | ok |
| **`branch`** (`br 0` con un valor **distinto**) | `00000000deadbeef` | `00000000deadbeef` | `00000000deadbeef` | ok |
| `unreachable` (el then-arm hace trap) | `0123456789abcdef` | `0123456789abcdef` | `0123456789abcdef` | ok |
| `nested` (un `if` dentro del then-arm) | `0123456789abcdef` | `0123456789abcdef` | `0123456789abcdef` | ok |
| `f32` (parametro f32) | `0000000040490fdb` | `0000000040490fdb` | `0000000040490fdb` | ok |

**0 desviaciones.** El `br` con un valor distinto —el caso que el test upstream no puede
distinguir— **funciona correctamente**: `Operator::Br` tambien llama a `emit_return_values()`
(`codegen.rs:3640`), con lo que copia y canonicaliza correctamente.

#### 2.9.4 La superficie alcanzable en produccion es muy estrecha

El limite `max_function_results` de `cosmwasm-vm` esta en **1** por defecto, y fetchd no lo
cambia (§2.10). El validador estatico de CosmWasm **rechaza los tipos de funcion con mas de un
resultado** (error medido: *"Wasm contract contains function with more than 1 results"*;
`cosmwasm-vm/packages/vm/src/compatibility.rs:313`), y por tanto tambien rechaza los bloques
multi-resultado. Como un `if` sin `else` exige que los parametros del bloque coincidan con sus
resultados, y un `if` con cero parametros y un resultado es Wasm invalido, la **única forma de
`if` con `else` implicito que puede llegar a produccion** es:

```wat
if (param T) (result T)      ;; T ∈ { i32, i64, f32, f64 }
```

Esto acota mucho la superficie: no hay bloques con parametros de tipos distintos, ni con mas de
un parametro, ni bloques con `f32`/`f64` mixtos. La matriz de §2.9.3 cubre las variantes
relevantes de esa superficie, y la de §2.9.2 el caso de coma flotante.

El limite vive en la **configuracion del nodo**, no en los parametros *on-chain*: un operador
que quisiera ampliar la superficie tendria que cambiar `wasmtypes.VMConfig{}` en
`app/app.go:709` y recompilar. En el estado actual del repositorio no hay ninguna via
*on-chain* para relajarlo.

**Lo que queda abierto:** `i32` con `enable_nan_canonicalization` no aplica (solo afecta a
floats); los bloques `(param i32)(result i32)` se comportan como los de `i64` (mismo tipo de
slot de 8 bytes). No se ha encontrado ninguna desviacion de valor en la superficie alcanzable.

### 2.10 La configuracion efectiva en fetchd, verificada extremo a extremo

Todo lo anterior se ha medido sobre el binario que fetchd carga de verdad. Esta seccion
cierra la cadena: **que version del stack ejecuta el nodo, que compilador elige, que limites
aplica y quien puede llegar al disparador.** Cada dato viene del codigo fuente del
repositorio y del commit exacto que el `go.mod` de fetchd fija.

**Cadena de versiones.** El `go.mod` de fetchd sustituye ambos componentes de CosmWasm por
forks privados de fetch.ai:

```go
// fetchd/go.mod
replace (
    github.com/CosmWasm/wasmd    => github.com/fetchai/priv_wasmd_sec   v0.61.15-rc.3  // ab17af8e72692541e5eb1b57c2d5480ed8084300
    github.com/CosmWasm/wasmvm/v3 => github.com/fetchai/priv_wasmvm_sec/v3 v3.0.8-rc.3   // d89faf180d3fb5de09b4ba59099844cc0a7a2632
)
```

En ese commit `d89faf18` de `priv_wasmvm_sec`, el `Cargo.lock` fija:

| componente | version |
|---|---|
| `cosmwasm-vm` | `3.0.10-rc.3` (fork `CosmWasm/priv_cosmwasm`, tag `v3.0.10-rc.3`) |
| `wasmer` | `7.4.2` |
| `wasmer-compiler-singlepass` | `7.4.2` |
| `wasmer-compiler-cranelift` | **ausente** |
| `wasmer-compiler-llvm` | **ausente** |

**Singlepass es el unico compilador que puede usar el nodo.** No es una opcion: en
`cosmwasm-vm` el motor se construye asi:

```rust
// cosmwasm-vm/packages/vm/src/wasm_backend/engine.rs:53
pub fn make_compiler_config() -> impl CompilerConfig + Into<Engine> {
    wasmer::sys::Singlepass::new()
}
```

(El propio test upstream lo afirma: `assert_eq!(cc.compiler().name(), "singlepass")`.) Por tanto
**no existe mitigacion por cambio de compilador**: Cranelift y LLVM, que canonicalizan distinto
o no canonicalizan, no estan presentes en el binario.

**La canonicalizacion de NaN esta activa en produccion.** `Singlepass::new()` construye la
configuracion con el default, que la activa:

```rust
// wasmer 7.4.2, lib/compiler-singlepass/src/config.rs:102
enable_nan_canonicalization: true,
```

(En Cranelift el default es `false`, `config.rs:133`.) Esto confirma que el hallazgo de §2.9.2
no es una rareza de laboratorio: es exactamente el modo en que el nodo ejecuta los contratos.

**Los limites de validacion estan en su default.** fetchd construye el VM con la configuracion
vacia:

```go
// fetchd/app/app.go:709
wasmtypes.VMConfig{},
```

`types.VMConfig` solo contiene `WasmLimits`, y `NodeConfig` no lo incluye, asi que **todos los
limites toman el valor por defecto de `cosmwasm-vm`**:

| limite | default | efecto |
|---|---|---|
| `max_function_results` | **1** | un bloque `if` solo puede tener 1 resultado |
| `max_function_params` | 100 | parametros por bloque/funcion |
| `max_function_locals` | 100 | locales por funcion |
| `max_functions` | 20 000 | funciones por modulo |
| `max_imports` | 100 | imports por modulo |

El limite `max_function_results = 1` es la razon exacta del error *"Wasm contract contains
function with more than 1 results"* que se midio en §2.9.4, y es lo que acota la superficie a
`if (param T)(result T)`. No es un limite *on-chain*: vive en la configuracion del nodo, y en
fetchd esta hardcodeada —subirla exigiria recompilar el binario del nodo.

**Los limites de memoria no protegen el stack nativo.** `contractMemoryLimit = 32` MiB se aplica
como `InstanceMemoryLimitBytes`, es decir, a la memoria *Wasm del contrato*. El stack que se
agota en §2.8 es el **stack nativo del JIT de Wasmer** (1 MiB, con guard page), que no es la
memoria del guest y no esta sujeto a ese limite. Por eso el fallo aparece como `SIGSEGV` y no
como un error de gas o de memoria.

**El disparador es permissionless.** Los parametros por defecto del modulo `wasm` de wasmd son:

```go
// wasmd v0.61.x, x/wasm/types/params.go:87
func DefaultParams() Params {
    return Params{
        CodeUploadAccess:             AllowEverybody,
        InstantiateDefaultPermission: AccessTypeEverybody,
    }
}
```

`CodeUploadAccess = AllowEverybody` significa que **cualquier cuenta puede subir un contrato
Wasm y ejecutarlo**; no hace falta permiso de gobernanza ni de lista blanca. La unica requisito es
pagar el gas de la transaccion, que para la forma fatal de §2.8 es **4 652 gas de SDK**
(§2.8.5), frente a un techo de bloque de 2 000 000 gas.

En resumen, la cadena de ataque verificada es:

```
cualquier cuenta
  -> StoreCode (AllowEverybody)          -> un Wasm de ~1 KiB
  -> InstantiateContract                  -> ejecuta `instantiate`
  -> el `else` implicito en bucle          -> 8 bytes de stack por iteracion
  -> 131 539 iteraciones                  -> 4 652 gas de SDK
  -> guard page del stack nativo de Wasmer-> SIGSEGV
  -> muerte del proceso del nodo
```

### 2.11 Impacto

**Sobre la cadena:** la transaccion atacante **no** se aplica (el estado se revierte), pero el
**proceso del nodo muere** (§2.8). Es una parada del nodo reproducible y permissionless, al
precio de 4 652 gas de SDK.

**Sobre otros contratos:** el defecto no discrimina por quien llama: cualquier contrato
legitimo que ejecute mas de ~131 000 `if` con `else` implicito, parametro de bloque y presion de
registros **falla**, aunque su logica sea correcta. Es un fallo de disponibilidad *de terceros*,
deterministico y reproducible. Con la forma de §2.8, ese mismo contrato ajeno puede **matar el
proceso**.

**Sobre el atacante:** obtiene una denegacion de servicio contra el nodo por 4 652 gas de SDK.
**No** obtiene robo de fondos, **no** obtiene ejecucion de codigo y **no** obtiene corrupcion
del estado de la cadena.

**Sobre la semantica (hallazgo 1c):** el atacante no controla el payload del NaN (lo produce el
hardware), pero **si** controla que el contrato use la forma implicita, y por tanto que el
resultado flotante dependa de la CPU. El efecto medido es una **ramificacion divergente** con
estado distinto del contrato (§2.9.2): es un vector de **divergencia de app hash**, no de robo.
La hipotesis de *exfiltracion* de datos mediante esta via sigue sin demostrarse.

### 2.12 Recomendacion

1. **Backport del fix upstream** `e5ca9b938` a la rama de Singlepass 7.4.2 usada por
   `priv_wasmvm_sec`, o migrar a una release de Wasmer que lo contenga cuando exista.
   Es una modificacion de ~131 lineas en `lib/compiler-singlepass/src/codegen.rs`.
   **Es la unica medida que cierra tanto la forma de trampa limpia como la escalada de §2.8**:
   ambas nacen de la misma omision de `emit_if_block_end()`.
2. **Auditar contratos legitimos** desplegados en fetchhub que usen `if` con parametro de bloque
   y `else` implicito en bucles largos: son las victimas reales del defecto.
2b. **Auditar contratos con coma flotante** antes de aplicar el backport: los que producen un
   NaN (`sqrt`, `floor`, `ceil`, `trunc`, `nearest`, `add/sub/mul/div` con operandos invalidos) y
   lo pasan como parametro de bloque a un `if` con `else` implicito **cambian de resultado** al
   aplicar el fix (§2.9.2). Si alguno ramifica sobre los bits del float, el **app hash cambia**
   en el momento de la actualizacion del nodo.
3. **Mitigacion de defensa en profundidad** (independiente del compilador): hacer que el manejador
   de trampas de Wasmer trate como irrecuperable **cualquier** `SIGSEGV` cuyo `SP` este fuera
   de la pila Wasm **y** restaurar la pila nativa antes de volver a ejecutar la instruccion — o,
   mas simple, abortar el proceso de forma controlada en lugar de dejar que el `SIGSEGV` lo
   mate. El defecto de §2.8 es una consecuencia directa de que Wasmer re-ejecute la instruccion
   que fallo con `SIG_DFL` restaurado.
4. **Limite de gas por contrato** como contencion: el disparador cuesta 4 652 gas de SDK, muy
   por debajo de cualquier limite razonable por transaccion, asi que el limite de gas **no**
   mitiga este caso (a diferencia de otros DoS).

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

# --- escalada a muerte del proceso (§2.8) ---
# barrido de la frontera exacta: <=131538 -> trampa recuperable, >=131539 -> SIGSEGV
python3 escalate.py --from 131530 --to 131545 --prefix 4

# sonda de fallo con SA_ONSTACK: direccion de fallo, RSP y RIP en la frontera
python3 escalate.py --from 131536 --to 131541 --prefix 4 --fault-probe

# matriz de evidencia: umbral fatal + coste en gas por tamano de pila
python3 escalation_matrix.py --prefix 4 --stacks 512K,1M,2M

# --- canonicalizacion de NaN (§2.9.2) ---
# bits del f64 y RAMIFICACION divergente entre `else` implicito y explicito
python3 nan_canon_probe.py

# --- matriz de formas: semantica de valores (§2.9.3) ---
python3 shape_matrix.py
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
* ~~No se ha probado una forma válida que salte completamente la página de guarda de 4 KiB~~ —
  **resuelto**: §2.8 documenta una forma válida que hace que el `SIGSEGV` se produzca con
  `SP < limit`, que es la condición real de irrecuperabilidad. La ausencia de muertes de proceso
  ya no es una afirmacion: hay una reproduccion (§2.8).
* La escalada de §2.8 se ha medido sobre el `.so` de producción (`libwasmvm.x86_64.so`,
  v3.0.8-rc.3), que es el artefacto exacto que fetchd v0.15.1 envia a fetchhub-4. **No** se ha
  reproducido dentro de un `wasmd` real: la muerte del proceso se observa a nivel de la libreria
  (SIGSEGV del proceso que la carga), que es el mismo mecanismo por el que moriria el validador.
* La forma de §2.8 depende de la pila Wasm de 1 MiB por defecto de Wasmer. Si el fork privado
  de `priv_wasmvm_sec` configurase `VMConfig::wasm_stack_size`, el umbral cambiaría
  proporcionalmente; el `.so` de producción **no exporta** ningun setter de ese tamaño, asi que
  se usa el valor por defecto.
* La busqueda de una via de *manipulacion del flujo de control* o *exfiltracion* (distinta de la
  escalada a muerte de proceso) **sigue abierta**: §2.9.2 demuestra una **ramificacion divergente**
  por la perdida de la canonicalizacion de NaN, pero **no** una exfiltracion de datos ni una
  corrupcion del estado de la cadena; el vector medido es de divergencia de app hash.
* La cobertura de la sonda de integridad sigue limitada a la forma `(param i64) (result i64)` con
  presion de registros. **No** cubre: bloques con parametros de tipos mixtos, `br` hacia fuera de
  un `if` con `else` implicito, `select`, `memory.copy` con direcciones solapadas, ni la
  interaccion con otros bloques anidados. La forma de coma flotante se ha cubierto aparte
  (§2.9.2) y **si** muestra una diferencia.
* No se ha auditado el resto de la superficie de `fetchd` (módulos custom, IBC2,
  ICA, tokenfactory) en esta iteración.
* El advisory `GHSA-v2h8-j899-r676` sigue sin corroboración pública (404 en la API de
  GitHub) y **no debe citarse como confirmado**.
