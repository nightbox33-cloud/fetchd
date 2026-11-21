import sys
import os
import subprocess, json, sys

def run(iters, prefix):
    cfg = dict(param_count=1, prefix_count=prefix, iterations=iters, explicit_else=False, condition=0, body="empty")
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cfg.json'),'w') as f:
        f.write(json.dumps(cfg))
    r = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "child_drift.py")], capture_output=True, text=True, timeout=300)
    out = r.stdout + r.stderr
    if "call stack exhausted" in out: return "TRAP"
    if '\"ok\"' in out and "DONE" in out: return "OK"
    return f"OTHER({r.returncode})"

def bisect(prefix, lo=120000, hi=150000):
    s = run(lo, prefix)
    if s != "OK":
        print(f"prefix={prefix} lo={lo} -> {s} (unexpected)"); return None
    s = run(hi, prefix)
    if s != "TRAP":
        print(f"prefix={prefix} hi={hi} -> {s} (unexpected)"); return None
    while hi - lo > 1:
        mid = (lo + hi)//2
        s = run(mid, prefix)
        if s == "TRAP": hi = mid
        else: lo = mid
    print(f"prefix={prefix}: lastOK={lo} firstTRAP={hi} leak@trap={hi*8}B initial={1048576-hi*8}B", flush=True)
    return hi

for p in [4, 8, 16, 24, 32, 48, 64]:
    bisect(p)
