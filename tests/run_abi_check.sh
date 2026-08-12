#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# ABI / calling-convention regression test.
#
# Compiles nothing at run time -- the fixture .obj was compiled with
# ti-cgt-c2000 (cl2000.exe) once and checked in. This harness:
#   1. Recompiles the .sla and reinstalls the module into $GHIDRA_INSTALL_DIR
#      (so cspec changes take effect -- Ghidra caches the compiled spec).
#   2. Headless-imports tests/fixtures/abi_probe.obj as a TMS320C28x program.
#   3. Runs DumpProtos.java, which calls PrototypeModel.getStorageLocations()
#      for each ABI probe signature -- a direct test of the .cspec, not of
#      Ghidra's body-analysis heuristics.
#   4. Diffs the emitted lines against tests/abi_probe.expected.txt.
#
# The expected file records the SPRU514 / SPRAC71 truth. To regenerate it after
# a deliberate cspec change, run with -update.
#
# Env:
#   GHIDRA_INSTALL_DIR -- required. Root of Ghidra install.
#
# Usage:
#   tests/run_abi_check.sh
#   tests/run_abi_check.sh -update       # rewrite expected file (careful!)

set -euo pipefail

module=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
. "$(dirname "${BASH_SOURCE[0]}")/_env.sh"; _c28x_load_env "$module"

: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR (or put it in .c28x.env) -- your Ghidra install root}"

update=0
[[ "${1:-}" == "-update" ]] && update=1

lang="$module/data/languages"
tmp=$(mktemp -d -t c28x-abi-XXXXXX)
trap 'rm -rf "$tmp"' EXIT

# 1. Compile the .sla and install alongside Module.manifest (mirror of run_disasm_test).
(cd "$lang" && "$GHIDRA_INSTALL_DIR/support/sleigh" tms320c28x.slaspec >/dev/null)
[ -f "$lang/tms320c28x.sla" ] || { echo "SLEIGH compile failed (no .sla)"; exit 1; }

modroot="$GHIDRA_INSTALL_DIR/Ghidra/Processors/TMS320C28x"
inst="$modroot/data/languages"
mkdir -p "$inst"
cp "$lang"/* "$inst/"
cp "$module/Module.manifest" "$modroot/Module.manifest"

mkdir -p "$tmp/proj" "$tmp/scripts"
cp "$module/ghidra_scripts/DumpProtos.java" "$tmp/scripts/DumpProtos.java"

# 2 + 3. Import + run DumpProtos. -noanalysis: skip auto-analysis, we only need
# the CompilerSpec object -- no need to run the (slow, noisy) decompiler.
raw=$("$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$tmp/proj" "abi_probe" \
    -import "$module/tests/fixtures/abi_probe.obj" \
    -processor "TMS320C28x:LE:32:default" \
    -scriptPath "$tmp/scripts" -postScript DumpProtos.java \
    -noanalysis -overwrite 2>&1) || {
    echo "$raw"; echo "headless analyzeHeadless failed"; exit 1;
}

# Pull the block between the DumpProtos sentinels; strip Ghidra's
# "DumpProtos.java> " prefix that println() gets wrapped in.
got=$(printf '%s\n' "$raw" \
    | awk '/=== DUMPPROTOS ===/{f=1;next} /=== END ===/{f=0} f' \
    | sed 's/^[^>]*> //')

expected="$module/tests/abi_probe.expected.txt"

if [ $update -eq 1 ]; then
    printf '%s\n' "$got" > "$expected"
    echo "wrote $expected ($(wc -l < "$expected") lines)"
    exit 0
fi

if [ ! -f "$expected" ]; then
    echo "no expected file yet; run '$0 -update' to seed it. actual output:"
    printf '%s\n' "$got"
    exit 2
fi

if diff -u "$expected" <(printf '%s\n' "$got"); then
    echo "PASS: $(wc -l < "$expected") lines match"
else
    echo "FAIL: cspec output differs from tests/abi_probe.expected.txt"
    exit 1
fi
