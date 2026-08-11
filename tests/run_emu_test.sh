#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# C28x SLEIGH *semantics* regression test.
#
# run_disasm_test.sh checks the listing; this checks what the p-code actually does, by
# emulating the FPU status-flag instructions and reading the STF sub-registers back.
# It is the only test that can catch a wrong bit order inside a mask -- SETFLG's FLAG
# field is split across both instruction words with the halves in the opposite order
# from the #16FHi immediates, and swapping them moves RND32 onto NI while the
# disassembly still looks entirely plausible.
#
# Assumes the language is already installed (run run_disasm_test.sh first, which
# compiles and installs it).
#
# Env:
#   GHIDRA_INSTALL_DIR  -- required. Root of Ghidra install.

set -euo pipefail

: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR to your Ghidra install root}"

module=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d -t c28x-emu-XXXXXX)
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/proj" "$tmp/scripts"
cp "$module/ghidra_scripts/EmuFlagTest.java" "$tmp/scripts/"
cp "$module/tests/fpu_flags.bin" "$tmp/"

# `|| true` so a headless failure is reported through the PASS check below rather than
# aborting under `set -e` with its output swallowed.
raw=$("$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$tmp/proj" emu \
  -import "$tmp/fpu_flags.bin" -processor "TMS320C28x:LE:32:default" \
  -scriptPath "$tmp/scripts" -postScript EmuFlagTest.java -noanalysis -overwrite 2>&1) || true

printf '%s\n' "$raw" | grep -E 'EmuFlagTest\.java> (PASS|FAIL)' || true

if printf '%s\n' "$raw" | grep -q 'EmuFlagTest\.java> PASS'; then
  echo "emulation semantics: OK"
else
  echo "--- emulation test did not pass; full analyzeHeadless output follows ---" >&2
  printf '%s\n' "$raw" >&2
  exit 1
fi
