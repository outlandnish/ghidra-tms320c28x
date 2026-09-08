#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# C28x SLEIGH *semantics* regression tests.
#
# run_disasm_test.sh checks the listing; these check what the p-code actually does, by
# emulating and reading registers back. Suites:
#
#   EmuFlagTest     -- SETFLG / SAVE / RESTORE against the STF sub-registers. The only
#                      test that can catch a wrong bit order INSIDE a mask: SETFLG's FLAG
#                      field is split across both instruction words with the halves in the
#                      opposite order from the #16FHi immediates, and swapping them moves
#                      RND32 onto NI while the disassembly still looks entirely plausible.
#
#   EmuFpuCondTest  -- the TMU_COND_OPERAND / FPU_MINMAX_FLUSH conditioning intrinsics.
#                      These are pcodeops, so their behaviour lives in the compiled
#                      TMS320C28xEmulateInstructionStateModifier and nothing else can see
#                      it. Requires the modifier jar, so build_modifier.sh must have run.
#
# Prerequisites, in order:
#   tests/run_disasm_test.sh   -- compiles and installs the language
#   tests/build_modifier.sh    -- compiles and installs the modifier jar
#
# Env:
#   GHIDRA_INSTALL_DIR  -- required. Root of Ghidra install.

set -euo pipefail

module=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# Load this worktree's local config (.c28x.env) if present, so the harness targets
# the Ghidra this worktree pins. Absent file => no-op (this is why CI is unaffected).
. "$(dirname "${BASH_SOURCE[0]}")/_env.sh"; _c28x_load_env "$module"

: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR (or put it in .c28x.env) -- your Ghidra install root}"

tmp=$(mktemp -d -t c28x-emu-XXXXXX)
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/proj" "$tmp/scripts"
cp "$module/ghidra_scripts/EmuFlagTest.java" "$tmp/scripts/"
cp "$module/ghidra_scripts/EmuFpuCondTest.java" "$tmp/scripts/"
cp "$module/ghidra_scripts/EmuRptTest.java" "$tmp/scripts/"
cp "$module/ghidra_scripts/EmuCallTest.java" "$tmp/scripts/"
cp "$module/ghidra_scripts/EmuLcTest.java" "$tmp/scripts/"
cp "$module/ghidra_scripts/EmuZalrTest.java" "$tmp/scripts/"
cp "$module/ghidra_scripts/EmuAluStoreTest.java" "$tmp/scripts/"
cp "$module/ghidra_scripts/EmuAddbAccFlagsTest.java" "$tmp/scripts/"
cp "$module/ghidra_scripts/EmuSubbAccFlagsTest.java" "$tmp/scripts/"
cp "$module/ghidra_scripts/EmuPreadFlagsTest.java" "$tmp/scripts/"
cp "$module/ghidra_scripts/EmuPreadRepeatTest.java" "$tmp/scripts/"
cp "$module/ghidra_scripts/EmuC2xlpTest.java" "$tmp/scripts/"
cp "$module/ghidra_scripts/EmuFlagsShiftAddTest.java" "$tmp/scripts/"
cp "$module/ghidra_scripts/EmuFlagsPmProductTest.java" "$tmp/scripts/"
cp "$module/ghidra_scripts/EmuFlagsMovbAxTest.java" "$tmp/scripts/"
cp "$module/ghidra_scripts/EmuFlagsLoneFamilyTest.java" "$tmp/scripts/"
cp "$module/ghidra_scripts/EmuOvcTest.java" "$tmp/scripts/"
cp "$module/ghidra_scripts/EmuMacOvcTest.java" "$tmp/scripts/"
cp "$module/ghidra_scripts/EmuShiftAuditTest.java" "$tmp/scripts/"
cp "$module/ghidra_scripts/EmuNegAbsTest.java" "$tmp/scripts/"
cp "$module/ghidra_scripts/EmuCmpLogicBitTest.java" "$tmp/scripts/"
cp "$module/tests/fpu_flags.bin" "$module/tests/fpu_cond.bin" "$tmp/"

fail=0
run_suite() {  # <script-basename> <fixture-basename>
  local script="$1" fixture="$2" raw
  echo "=== $script ==="
  # `|| true` so a headless failure is reported through the PASS check rather than
  # aborting under `set -e` with its output swallowed.
  raw=$("$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$tmp/proj" "e_$script" \
    -import "$tmp/$fixture" -processor "TMS320C28x:LE:32:default" \
    -scriptPath "$tmp/scripts" -postScript "$script.java" -noanalysis -overwrite 2>&1) || true

  printf '%s\n' "$raw" | grep -E "$script\.java> (PASS|FAIL)" || true
  if ! printf '%s\n' "$raw" | grep -q "$script\.java> PASS"; then
    echo "--- $script did not pass; full analyzeHeadless output follows ---" >&2
    printf '%s\n' "$raw" >&2
    fail=1
  fi
}

run_suite EmuFlagTest fpu_flags.bin
run_suite EmuFpuCondTest fpu_cond.bin
run_suite EmuRptTest fpu_flags.bin  # host-driven test, any C28x program will do as import target
run_suite EmuCallTest fpu_flags.bin # RPC nested-call chain (state modifier, not SLEIGH)
run_suite EmuLcTest fpu_flags.bin   # LC/LRET software-stack call, RPC untouched (#77)
run_suite EmuZalrTest fpu_flags.bin # ZALR single ACC store; no firmware site covers it
run_suite EmuAluStoreTest fpu_flags.bin     # store-side loc16,AX ALU trio (issue #56)
run_suite EmuAddbAccFlagsTest fpu_flags.bin # ADDB ACC,#8bit Z/N/C/V (host-driven)
run_suite EmuSubbAccFlagsTest fpu_flags.bin # SUBB ACC,#8bit Z/C  (the fill-loop hole)
run_suite EmuPreadFlagsTest fpu_flags.bin   # PREAD loc16,*XAR7 N/Z (host-driven)
run_suite EmuPreadRepeatTest fpu_flags.bin  # RPT||PREAD *XAR7 shadow (state modifier)
run_suite EmuC2xlpTest fpu_flags.bin        # C2xLP 0x3F page + XCALL/XRET software stack
run_suite EmuFlagsShiftAddTest fpu_flags.bin  # issue #90 group A: shift-form ACC arithmetic
run_suite EmuFlagsPmProductTest fpu_flags.bin # issue #90 group B: ADDL/SUBL ACC,P<<PM
run_suite EmuFlagsMovbAxTest fpu_flags.bin    # issue #90 group C: MOVB AX.LSB/MSB N/Z
run_suite EmuFlagsLoneFamilyTest fpu_flags.bin # issue #90 group D: lone-family + SFR SXM
run_suite EmuOvcTest fpu_flags.bin            # issue #93: OVC counter + SAT ACC + OVM=1
run_suite EmuMacOvcTest fpu_flags.bin         # issue #95: MAC-family + ADDC/SBBU OVC accounting
run_suite EmuShiftAuditTest fpu_flags.bin     # issue #104: AX + 64-bit shift N/Z/C, LSL/SFR ACC,T + ROR ACC
run_suite EmuNegAbsTest fpu_flags.bin         # issue #106: NEG/ABS/NEGTC/ABSTC + OVM saturation
run_suite EmuCmpLogicBitTest fpu_flags.bin    # issue #108: Compare/Logical/Bit-manip audit

if [ "$fail" -eq 0 ]; then
  echo "emulation semantics: OK"
else
  exit 1
fi
