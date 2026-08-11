#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# C28x SLEIGH disassembler regression test.
#
# 1. Recompiles the .sla, 2. reinstalls it into Ghidra, 3. headless-disassembles
# tests/addr_modes.bin, 4. diffs against tests/addr_modes.expected.txt.
#
# Env / args:
#   GHIDRA_INSTALL_DIR  -- required. Root of Ghidra install.
#
# Expected output (verified 2026-06-22, all 14 cases pass):
#   0x0000  0606      MOVL ACC,@0x6
#   0x0001  8006      MOVL ACC,*XAR0++
#   0x0002  8b06      MOVL ACC,*--XAR3
#   0x0003  9206      MOVL ACC,*+XAR2[AR0]
#   0x0004  9b06      MOVL ACC,*+XAR3[AR1]
#   0x0005  d506      MOVL ACC,*+XAR5[0x2]
#   0x0006  a106      MOVL ACC,@XAR1
#   0x0007  bd06      MOVL ACC,*SP++
#   0x0008  be06      MOVL ACC,*--SP
#   0x0009  0707      ADDL ACC,@0x7
#   0x000a  0420      MOV @0x4,IER
#   0x000b  04283412  MOV @0x4,#0x1234
#   0x000d  0100      ABORTI
#   0x000e  2176      IDLE

set -euo pipefail

: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR to your Ghidra install root}"

module=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
lang="$module/data/languages"
tmp=$(mktemp -d -t c28x-test-XXXXXX)
trap 'rm -rf "$tmp"' EXIT

# 1. compile the .sla
(cd "$lang" && "$GHIDRA_INSTALL_DIR/support/sleigh" tms320c28x.slaspec)
[ -f "$lang/tms320c28x.sla" ] || { echo "SLEIGH compile failed (no .sla)"; exit 1; }

# 2. reinstall into Ghidra. On a fresh Ghidra the TMS320C28x module does not exist
# yet, so also drop in the Module.manifest -- without it Ghidra won't treat the
# directory as a module and won't discover the language (analyzeHeadless then fails
# with "language not found"). data/languages is enough to load + disassemble here;
# the compiled Java (emulate modifier / analyzer) is resolved lazily and is not
# needed for this -noanalysis decode check.
modroot="$GHIDRA_INSTALL_DIR/Ghidra/Processors/TMS320C28x"
inst="$modroot/data/languages"
mkdir -p "$inst"
cp "$lang"/* "$inst/"
cp "$module/Module.manifest" "$modroot/Module.manifest"

# 3. headless disassemble
mkdir -p "$tmp/proj" "$tmp/scripts"
cp "$module/tests/addr_modes.bin" "$tmp/addr_modes.bin"
cp "$module/ghidra_scripts/DumpDisasm.java" "$tmp/scripts/DumpDisasm.java"
# `|| true`: don't let a headless failure abort under `set -e` before we can print
# its output -- an empty $got below is reported as a diagnostic instead of a blank.
raw=$("$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$tmp/proj" t \
  -import "$tmp/addr_modes.bin" -processor "TMS320C28x:LE:32:default" \
  -scriptPath "$tmp/scripts" -postScript DumpDisasm.java -noanalysis -overwrite 2>&1) || true

# 4. compare. Pull "ADDR<tab>BYTES<tab>TEXT" lines from DumpDisasm's println output;
# strip Ghidra's "<script>> " prefix + optional "<space>MEM:" address prefix, then
# left-pad-strip leading zeros so "0000" -> "0x0" matches the "0x0" in expected.
got=$(printf '%s\n' "$raw" \
  | sed -n 's/.*DumpDisasm\.java> //p' \
  | sed -E 's/ \(GhidraScript\)[[:space:]]*$//' \
  | sed -E 's/^[A-Za-z]+:0*/0x/' \
  | sed -E 's/^0*([0-9a-fA-F])/0x\1/' \
  | grep -E '^0x[0-9a-fA-F]' || true)

echo "--- GOT ---"
printf '%s\n' "$got"
if [ -z "$got" ]; then
  echo "--- no disassembly parsed; raw analyzeHeadless output follows ---" >&2
  printf '%s\n' "$raw" >&2
fi

exp="$module/tests/addr_modes.expected.txt"
fail=0
lineno=0
while IFS= read -r e; do
  lineno=$((lineno + 1))
  g=$(printf '%s\n' "$got" | sed -n "${lineno}p")
  [ -n "$g" ] || g="<missing>"
  # 3rd tab-field (mnemonic + operands); strip "0x" so hex-formatting drift doesn't fail.
  et=$(printf '%s' "$e" | awk -F'\t' '{print $3}')
  gt=$(printf '%s' "$g" | awk -F'\t' '{print $3}')
  etn=${et//0x/}
  gtn=${gt//0x/}
  if [ "$etn" != "$gtn" ]; then
    printf 'FAIL line %d: expected [%s] got [%s]\n' "$lineno" "$et" "$gt" >&2
    fail=$((fail + 1))
  fi
done < "$exp"

total=$lineno
if [ "$fail" -eq 0 ]; then
  printf 'PASS: all %d cases\n' "$total"
else
  printf '%d FAILURES\n' "$fail" >&2
  exit 1
fi
