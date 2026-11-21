import sys
import os
import subprocess, json

def run(cfg, timeout=120):
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cfg.json'),'w') as f:
        f.write(json.dumps(cfg))
    result = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "child_drift.py")], capture_output=True, text=True, timeout=timeout)
    out = result.stdout
    if "call stack exhausted" in out:
        status = "TRAP"
    elif '"ok"' in out and "DONE" in out:
        status = "OK"
    else:
        status = f"OTHER EXIT={result.returncode}"
    print(f"iters={cfg['iterations']} param={cfg['param_count']} prefix={cfg['prefix_count']} explicit={cfg['explicit_else']} cond={cfg['condition']} body={cfg['body']} -> {status}", flush=True)
    return status

print("=== Threshold ===")
for iters in [130000, 132000, 134000, 135000]:
    run(dict(param_count=1, prefix_count=32, iterations=iters, explicit_else=False, condition=0, body="empty"))

print("\n=== Prefix sweep (200k iters, implicit, false) ===")
for prefix in [0, 1, 2, 4, 8, 16, 31, 32]:
    run(dict(param_count=1, prefix_count=prefix, iterations=200000, explicit_else=False, condition=0, body="empty"))

print("\n=== Param sweep (200k, prefix=32) ===")
for param in [0, 1]:
    run(dict(param_count=param, prefix_count=32, iterations=200000, explicit_else=False, condition=0, body="empty"))

print("\n=== Condition sweep ===")
run(dict(param_count=1, prefix_count=32, iterations=200000, explicit_else=False, condition=0, body="empty"))
run(dict(param_count=1, prefix_count=32, iterations=200000, explicit_else=False, condition=1, body="empty"))
run(dict(param_count=1, prefix_count=32, iterations=200000, explicit_else=True, condition=0, body="empty"))
run(dict(param_count=1, prefix_count=32, iterations=200000, explicit_else=True, condition=1, body="empty"))
