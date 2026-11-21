import sys
import os
import subprocess, json, sys

def run(iters, prefix=32, param=1, explicit=False, condition=0):
    cfg = dict(param_count=param, prefix_count=prefix, iterations=iters, explicit_else=explicit, condition=condition, body="empty")
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cfg.json'),'w') as f:
        f.write(json.dumps(cfg))
    r = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "child_drift.py")], capture_output=True, text=True, timeout=300)
    out = r.stdout + r.stderr
    if "call stack exhausted" in out: return "TRAP", out
    if '\"ok\"' in out and "DONE" in out: return "OK", out
    return f"OTHER({r.returncode})", out

lo, hi = 128000, 140000
# ensure lo OK, hi TRAP
s,_ = run(lo); print("lo", lo, s, flush=True)
if s != "OK":
    print("lo not OK, adjusting"); sys.exit(1)
s,_ = run(hi); print("hi", hi, s, flush=True)
if s != "TRAP":
    print("hi not TRAP, adjusting"); sys.exit(1)
while hi - lo > 1:
    mid = (lo + hi)//2
    s,out = run(mid)
    print("mid", mid, s, flush=True)
    if s == "TRAP": hi = mid
    else: lo = mid
print(f"EXACT_THRESHOLD: first trap at iters={hi}, last ok={lo}", flush=True)
print(f"leak_bytes_at_threshold = {hi*8} ({hi*8/1048576:.6f} MiB)", flush=True)
