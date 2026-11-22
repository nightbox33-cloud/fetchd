# PoC — Singlepass "implicit else" en fetchd

Pruebas de concepto de la auditoría descrita en [`AUDIT_REPORT.md`](AUDIT_REPORT.md).

Todas las pruebas cargan el **binario de producción real**
(`fetchai/priv_wasmvm_sec` `v3.0.8-rc.3` → `internal/api/libwasmvm.x86_64.so`)
mediante `ctypes`, usando la ABI C de CosmWasm. No hace falta toolchain Rust ni Go.

## Preparación

```sh
./build_sp.sh                       # sonda de stack nativo (solo para measure_drift/context_probe)
```

El `.so` de producción se espera en
`.audit/priv_wasmvm_sec/internal/api/libwasmvm.x86_64.so`
(ruta configurable en `run_poc.py`, constante `LIB`).

## Scripts principales

| Script | Qué hace |
|---|---|
| `wasm_builder.py` | Generador de módulos Wasm binarios (secciones, ULEB, tipos, imports, bloques) |
| `run_poc.py` | Harness `ctypes` contra la ABI C de CosmWasm: store/instantiate/execute, captura de señal, mapas de memoria |
| `upstream_faithful.py` | **Test de regresión upstream reconstruido byte a byte** (`implicit_else_reclaims_inputs`): matriz completa, frontera valor/pila y caso individual |
| `integrity_probe.py` | **Oráculo diferencial de valores**: `else` implícito vs. `else` explícito (equivalente al implícito según la especificación) + centinelas de pila nativa |
| `trigger_shape.py` | Forma exacta del disparador: dependencia de la rama, umbral por búsqueda binaria, bytes fugados por `if` |
| `reachability.py` | Presión de registros mínima que provoca la fuga y **alcance frente al `max_gas` de la cadena, con las unidades correctas** |
| `gas_units.py` | Conversión a gas del SDK y prueba con el presupuesto real de una tx |
| `upstream_matrix.py` | Matriz upstream histórica (body × param × prefix × condición) + formas desplegables + economía de gas |
| `upstream_regression.py` | Reconstrucción en Wasm crudo del test upstream (versión histórica; usar `upstream_faithful.py`) |
| `gas_economics.py` | Umbral exacto de disparo y coste de gas por iteración |
| `gas_ceiling.py` | Experimento decisivo: qué ocurre con el límite de gas real de una tx |
| **`escalate.py`** | **Escalada a muerte del proceso (§2.8 del informe)**: bucle que filtra pila *sin llamada* + `call` posterior. Barrido de la frontera exacta (`≤131538` → trampa recuperable, `≥131539` → `SIGSEGV`) y sonda de fallo con `SA_ONSTACK` |
| **`escalation_matrix.py`** | Matriz de evidencia de la escalada: umbral fatal, direcciones de fallo, control con `else` explícito y coste en gas de la VM y del SDK |
| **`signal_probe.py`** | Manejador de `SIGSEGV` con `SA_ONSTACK` + `sigaltstack` (igual que Wasmer): captura `si_addr`, `RSP`, `RIP` y el mapeo `/proc/self/maps` que contiene el `RIP` |

## Scripts de apoyo

| Script | Qué hace |
|---|---|
| `context_probe.py` | Compara ejecución en hilo principal vs hilo Python y vuelca `/proc/self/maps` |
| `measure_drift.py` | Muestreo del stack nativo vía callback de host |
| `fault_probe.py`, `fault_probe2.py` | Captura de la señal cruda: `si_code`, `si_addr`, `RSP`, `RIP` y el mapeo que contiene el `RIP`. **Nota:** `fault_probe.py` instala el manejador *sin* `SA_ONSTACK` (el README anterior afirmaba lo contrario), por lo que **no puede observar un fallo que ocurre sobre la pila agotada**: el kernel intenta empujar el marco de la señal sobre esa pila, el empuje falla también y el proceso muere antes. Para eso está `signal_probe.py`. |
| `drift_fault.py` | Diagnóstico del aterrizaje del SP desviado y mapa de memoria completo |
| `jit_analyze.py` | Extrae el código JIT del caché y calcula el balance de RSP de los bucles |
| `crash_test.py` | Matriz producción-like de muerte de proceso (600–4096 `if`/iteración) |
| `kill_sweep.py` | Barrido de muerte de proceso en subprocesos (72 variantes) |
| `differential.py` | Comparación semántica `else` implícito vs `else` explícito |
| `sweep_bodies.py` | Barrido de cuerpos y prefijos |
| `semantic_probe.py` | Sonda de valores implícito/explícito (ver la nota de corrección abajo) |

## Notas sobre el harness y sobre correcciones previas

**Harness.** La API C de CosmWasm puede devolver **un vector de respuesta presente pero vacío
junto con un vector de error con texto**. `run_poc.run_once` registra el vector de error
incondicionalmente; si no se hace así, el fallo se clasifica erróneamente como éxito.

**Unidades de gas.** El VM mide en *puntos de gas de CosmWasm*; la cadena presupuesta en *gas del
SDK*. La conversión es `DefaultGasMultiplier = 140_000` puntos por gas de SDK
(`wasmd/x/wasm/types/gas_register.go`). Comparar gas del SDK directamente con puntos de VM
introduce un factor de 140 000× y **concluye lo contrario de la verdad**: el disparador cuesta
**7 754 gas de SDK** (no 1,09 × 10⁹) y tiene **258× de holgura** bajo el `max_gas` de 2 000 000.

**Orientación de la sonda de valores.** El resultado de un bloque `if` queda **encima** de la pila
de valores; los valores empujados antes del `if` quedan *debajo*. Una sonda que captura el valor
después de hacer `drop` de los valores del prefijo está midiendo el valor equivocado y es
**incapaz de detectar una diferencia** entre `else` implícito y explícito. `integrity_probe.py`
captura el resultado antes de los `drop`; `semantic_probe.py` tenía ese defecto y fue corregido.

**Escalada a muerte del proceso (§2.8).** La fuga del `else` implícito no se limita a la trampa
`call stack exhausted`. Si el bucle que filtra pila **no contiene ninguna llamada**, el `RSP`
deriva por debajo de la página de guarda sin tocarla (`sub rsp, N` es una operación de registro
y los slots de valores son relativos a `RBP`); la `call` posterior empuja la dirección de
retorno en `RSP-8`, ya por debajo de `limit`, y Wasmer **no puede recuperar** el fallo
(`stack_ptr_in_bounds(sp) == false`): restaura `SIG_DFL`, la instrucción que falló se re-ejecuta
y el proceso **muere con `SIGSEGV`**. Umbral medido con el `.so` de producción y la pila Wasm de
1 MiB: **131 539 iteraciones** (4 652 gas de SDK). El control con `else` explícito no muere ni
con 200 000 iteraciones.

> **Para observar el fallo de una pila agotada hace falta `SA_ONSTACK`.** Un manejador instalado
> sin pila de señales alternativa no puede recibir el `SIGSEGV`: el kernel intenta empujar el
> marco de la señal sobre la pila agotada, ese empuje falla también y el proceso muere antes de
> que el manejador se ejecute. `fault_probe.py` instala la pila alternativa igual que Wasmer.

**Varios fallos son irrecuperables por diseño de Wasmer.** `handle_trap` devuelve `false` cuando
el `SP` está fuera de la pila Wasm; el manejador de señales restaura entonces `SIG_DFL` y
vuelve, de modo que la instrucción que falló se re-ejecuta y el proceso muere. Ése es
precisamente el mecanismo que convierte la fuga de Singlepass en una muerte de proceso.
