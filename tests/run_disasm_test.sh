#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# C28x SLEIGH disassembler regression test.
#
# 1. Recompiles the .sla, 2. reinstalls it into Ghidra, then for each case in
# $CASES: 3. headless-disassembles tests/<case>.bin, 4. diffs the mnemonic text
# against tests/<case>.expected.txt.
#
# Cases:
#   addr_modes   -- every AMODE=0 loc16/loc32 addressing mode (14 cases).
#   fpu_display  -- FPU operand RENDERING, where our text has to match TI's own
#                   assembler exactly: MOVST0's flag-select list, TESTTF's CNDF,
#                   and the split-field #16FHi immediates (whose value is spread
#                   across both instruction words, so a wrong reassembly prints a
#                   plausible-looking but wrong constant). Every expected line was
#                   verified against asm2000/dis2000 output for the same words.
#   fpu_parallel -- every parallel ("||") FPU form. These pack five register
#                   selectors plus a mem32 loc byte across both words, and TWO of
#                   the selectors straddle the word boundary in OPPOSITE bit
#                   orders (ReH = e:ee, RfH = ff:f), which is exactly the kind of
#                   thing that decodes plausibly while naming the wrong register.
#                   Assembled by asm2000 from the TI mnemonics, so the expected
#                   registers are TI's, not ours.
#   fpu_flags    -- SETFLG / SAVE / RESTORE. Their 11-bit FLAG mask is split across
#                   both words with the HIGH 6 bits in the LSW and the low 5 in the
#                   MSW -- the opposite order from the #16FHi immediates, and getting
#                   it backwards silently moves RND32 onto NI. Assembled by asm2000
#                   from TI mnemonics (`SETFLG RNDF32=1` -> e610 0200).
#
# Env / args:
#   GHIDRA_INSTALL_DIR  -- required. Root of Ghidra install.
#
# Expected output (verified 2026-06-22, all 14 addr_modes cases pass):
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

module=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# Load this worktree's local config (.c28x.env) if present, so the harness targets
# the Ghidra this worktree pins. Absent file => no-op (this is why CI is unaffected).
. "$(dirname "${BASH_SOURCE[0]}")/_env.sh"; _c28x_load_env "$module"

: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR (or put it in .c28x.env) -- your Ghidra install root}"

lang="$module/data/languages"
tmp=$(mktemp -d -t c28x-test-XXXXXX)
trap 'rm -rf "$tmp"' EXIT

CASES="addr_modes fpu_display fpu_parallel fpu_flags"

# 1. compile the .sla
(cd "$lang" && "$GHIDRA_INSTALL_DIR/support/sleigh" tms320c28x.slaspec)
[ -f "$lang/tms320c28x.sla" ] || { echo "SLEIGH compile failed (no .sla)"; exit 1; }

# 2. reinstall into Ghidra. On a fresh Ghidra the TMS320C28x module does not exist
# yet, so Install also drops in the Module.manifest -- without it Ghidra won't treat
# the directory as a module and won't discover the language (analyzeHeadless then
# fails with "language not found"). data/languages is enough to load + disassemble
# here; the compiled Java (emulate modifier / analyzer) is resolved lazily and is not
# needed for this -noanalysis decode check.
#
# _c28x_install_module writes to exactly ONE location -- the installed extension when
# there is one, else the Processors drop-in. Populating both makes Ghidra 12.1.2
# refuse to start ("Language ... previously defined").
_c28x_install_module "$GHIDRA_INSTALL_DIR" "$module" >/dev/null

mkdir -p "$tmp/proj" "$tmp/scripts"
cp "$module/ghidra_scripts/DumpDisasm.java" "$tmp/scripts/DumpDisasm.java"

fail=0
total=0
for name in $CASES; do
  echo "=== $name ==="

  # 3. headless disassemble
  cp "$module/tests/$name.bin" "$tmp/$name.bin"
  # `|| true`: don't let a headless failure abort under `set -e` before we can print
  # its output -- an empty $got below is reported as a diagnostic instead of a blank.
  raw=$("$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$tmp/proj" "t_$name" \
    -import "$tmp/$name.bin" -processor "TMS320C28x:LE:32:default" \
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

  exp="$module/tests/$name.expected.txt"
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
      printf 'FAIL %s line %d: expected [%s] got [%s]\n' "$name" "$lineno" "$et" "$gt" >&2
      fail=$((fail + 1))
    fi
  done < "$exp"
  total=$((total + lineno))
done

if [ "$fail" -eq 0 ]; then
  printf 'PASS: all %d cases\n' "$total"
else
  printf '%d FAILURES\n' "$fail" >&2
  exit 1
fi
