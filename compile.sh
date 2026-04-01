#!/bin/bash
# compile.sh — Run inside the container to compile the P4 program
# Usage: bash /opt/p4work/arp_flood_detection/compile.sh

set -e
BASE="/opt/p4work/arp_flood_detection"
SRC="$BASE/p4/arp_monitor.p4"
OUT="$BASE/build"

echo "[P4C] Compiling $SRC ..."
mkdir -p "$OUT"

p4c \
    --target bmv2 \
    --arch v1model \
    --std p4-16 \
    -o "$OUT" \
    "$SRC"

echo ""
echo "[P4C] Done. Output files:"
ls -lh "$OUT"/
echo ""
echo "[P4C] Verify JSON is valid:"
python3 -c "import json; json.load(open('$OUT/arp_monitor.json')); print('  JSON OK')"
