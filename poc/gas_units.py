#!/usr/bin/env python3
"""
Reachability of the Singlepass "implicit else" stack exhaustion with the
CORRECT gas units.

The earlier version of this analysis compared CosmWasm gas points with Cosmos
SDK gas.  They are not the same unit:

    wasmd/x/wasm/types/gas_register.go
        DefaultGasMultiplier = 140_000        "how many CosmWasm gas points = 1 SDK gas"
        ToWasmVMGas(sdk)   = sdk * 140_000   // SDK gas  -> VM gas points
        FromWasmVMGas(vm)  = vm  / 140_000   // VM gas points -> SDK gas

    wasmd/x/wasm/keeper/keeper.go
        runtimeGasForContract(ctx) = ToWasmVMGas(ctx.GasMeter().Limit() - GasConsumedToLimit())
        consumeRuntimeGas(ctx, gas) = ctx.GasMeter().ConsumeGas(FromWasmVMGas(gas))

So the gas limit handed to the VM is the SDK gas limit * 140,000, and the gas
actually charged to the transaction is the VM gas / 140,000.

This script redoes the experiment with the right unit on both sides.
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_poc as R                              # noqa: E402
from reachability import build                   # noqa: E402

MULT = 140_000          # wasmd DefaultGasMultiplier
CHAIN_MAX_GAS = 2_000_000   # fetchhub-3/4 consensus_params.block.max_gas


def run_with_vm_limit(iterations, prefix, vm_limit):
    """vm_limit is in CosmWasm gas points (what the C API expects)."""
    wasm = build(prefix, False, iterations)
    base = tempfile.mkdtemp()
    vm = R.VM()
    cache = vm.init_cache(base)
    checksum = vm.store_code(cache, wasm, checked=True)
    vm.instantiate(cache, checksum, vm_limit)
    res2, rep2, err2 = vm.execute(cache, checksum, vm_limit)
    err = vm._vec_str(err2)
    return err, rep2.used_internally


def main():
    print("Coste real del disparador en unidades de la cadena")
    print()
    print("   multiplicador wasmd (CosmWasm gas -> SDK gas): 1 / %d" % MULT)
    print("   max_gas de la cadena (fetchhub-3/4)           : %d SDK gas" % CHAIN_MAX_GAS)
    print("   limite de gas en puntos de CosmWasm           : %d" % (CHAIN_MAX_GAS * MULT))
    print()

    # 1) how many VM gas points does the trigger cost?
    vm_limit = 1 << 62
    err, used = run_with_vm_limit(400000, 4, vm_limit)
    vm_points = used
    sdk_gas = vm_points // MULT
    print("   coste del disparador : %d puntos de CosmWasm = %d gas de SDK"
          % (vm_points, sdk_gas))
    print("   frente a max_gas %d -> holgura %.0fx"
          % (CHAIN_MAX_GAS, CHAIN_MAX_GAS / float(sdk_gas)))
    print()

    # 2) with the chain's real ceiling, expressed in VM points
    print("   ejecutando con el limite REAL de una tx (%d SDK gas = %d puntos):"
          % (CHAIN_MAX_GAS, CHAIN_MAX_GAS * MULT))
    err, used = run_with_vm_limit(400000, 4, CHAIN_MAX_GAS * MULT)
    if "call stack exhausted" in err:
        print("      -> STACK EXHAUSTED: el disparador SE ALCANZA en una tx real")
    elif err:
        print("      -> otro error: %s" % err[:90])
    else:
        print("      -> completada sin error")
    print()

    # 3) how cheap can the tx be?
    print("   limite de gas minimo necesario (en puntos de CosmWasm):")
    lo, hi = 1, vm_points
    while lo < hi:
        mid = (lo + hi) // 2
        err, _ = run_with_vm_limit(400000, 4, mid)
        if "call stack exhausted" in err:
            hi = mid
        else:
            lo = mid + 1
    print("      %d puntos = %d gas de SDK (fee minimo a 5 atestfet/gas = %.6f FET)"
          % (lo, lo // MULT, lo / MULT * 5e9 * 1e-18))


if __name__ == "__main__":
    main()
