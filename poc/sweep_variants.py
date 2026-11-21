import sys
import os
import subprocess, json

def run(cfg, timeout=300):
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cfg.json'),'w') as f: f.write(json.dumps(cfg))
    try:
        r = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "child_drift.py")], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "TIMEOUT", "", ""
    out = r.stdout + r.stderr
    if "call stack exhausted" in out: st="STACK_OVERFLOW_TRAP"
    elif '"ok"' in out and "DONE" in out: st="OK"
    elif r.returncode != 0: st=f"CRASH_EXIT={r.returncode}"
    else: st=f"OTHER"
    return st, out, r.stderr

cases = [
 dict(param_count=1, prefix_count=32, iterations=300000, explicit_else=False, condition=1, body="replace"),
 dict(param_count=1, prefix_count=32, iterations=300000, explicit_else=True,  condition=1, body="replace"),
 dict(param_count=1, prefix_count=32, iterations=300000, explicit_else=False, condition=0, body="replace"),
 dict(param_count=1, prefix_count=32, iterations=300000, explicit_else=False, condition=0, body="branch"),
 dict(param_count=1, prefix_count=32, iterations=300000, explicit_else=True,  condition=0, body="branch"),
 dict(param_count=1, prefix_count=32, iterations=300000, explicit_else=False, condition=0, body="empty"),
 dict(param_count=1, prefix_count=32, iterations=300000, explicit_else=True,  condition=1, body="empty"),
 dict(param_count=1, prefix_count=0,  iterations=300000, explicit_else=False, condition=0, body="replace"),
]
for c in cases:
    st, out, err = run(c)
    print(f"{c} -> {st}", flush=True)
    if st not in ("OK","STACK_OVERFLOW_TRAP"):
        print(out[-1500:], err[-800:])
