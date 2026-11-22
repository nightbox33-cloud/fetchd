#!/bin/sh
# Builds the native stack probe used by measure_drift.py / context_probe.py.
#
#   cc -shared -fPIC -O2 -o libsp.so sp_probe.c
#
# The probe returns __builtin_frame_address(0), i.e. the address of the current
# native frame.  libc does not export that symbol, so a tiny shared object is
# the simplest way to sample the native stack pointer from a host callback.
set -e
cd "$(dirname "$0")"
cc -shared -fPIC -O2 -o libsp.so sp_probe.c
echo "built $(pwd)/libsp.so"
