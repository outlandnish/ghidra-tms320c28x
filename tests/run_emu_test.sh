#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# C28x SLEIGH *semantics* regression tests.
#
# run_disasm_test.sh checks the listing; these check what the p-code actually does, by
# emulating and reading registers back. Two suites:
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

if [ "$fail" -eq 0 ]; then
  echo "emulation semantics: OK"
else
  exit 1
fi
