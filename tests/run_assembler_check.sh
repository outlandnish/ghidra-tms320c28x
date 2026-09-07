#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# Assembler regression for SPLIT immediates -- operands whose bits are spread across
# both words of a two-word instruction: the 22-bit branch/call/pointer operand
# (LB / LC / LCR / FFC / MOVL XARn,#22bit) and the FPU #16FHi operand
# (MOVIZ / MOVXI / CMPF32 / MAXF32 / MINF32 / ADDF32 / MPYF32 / SUBF32).
#
# These are rejoined in a disassembly action, e.g.
#     [ xar22 = (loc_off6 << 16) | imm16; ]
# and Ghidra's assembler INVERTS that expression to solve for the fields. It can
# invert `|` over disjoint fields; it cannot invert `+`. Since the fields never
# overlap the two are numerically identical, so writing `+` breaks nothing about
# disassembly, emulation or the decompiler and every other test here still passes --
# only "Patch Instruction" and the WildcardAssembler stop working, on the pointer
# loads that are how this target names every peripheral. Hence a dedicated gate.
#
# Everything checked lives in ghidra_scripts/AssembleRoundTrip.java, including the
# expected encodings, so there is one source of truth and this harness only has to
# get Ghidra to run it.
#
# Env / args:
#   GHIDRA_INSTALL_DIR  -- required. Root of Ghidra install (or set it in .c28x.env).
#
# Usage:  bash tests/run_assembler_check.sh
set -euo pipefail

module=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
. "$(dirname "${BASH_SOURCE[0]}")/_env.sh"; _c28x_load_env "$module"

: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR (or put it in .c28x.env) -- your Ghidra install root}"

lang="$module/data/languages"
tmp=$(mktemp -d -t c28x-asm-XXXXXX)
trap 'rm -rf "$tmp"' EXIT

# Compile + install, same as the disassembler regression: this must test the spec in
# the tree, not whatever .sla was installed last.
(cd "$lang" && "$GHIDRA_INSTALL_DIR/support/sleigh" tms320c28x.slaspec)
[ -f "$lang/tms320c28x.sla" ] || { echo "SLEIGH compile failed"; exit 1; }
_c28x_install_module "$GHIDRA_INSTALL_DIR" "$module" >/dev/null

mkdir -p "$tmp/proj" "$tmp/scripts"
cp "$module/ghidra_scripts/AssembleRoundTrip.java" "$tmp/scripts/AssembleRoundTrip.java"

# headless needs SOMETHING to import to get a Program (the assembler reads its
# starting context from one). The script builds its own corpus in a block it
# creates, so this stub is four words of nothing and its content is irrelevant.
head -c 8 /dev/zero > "$tmp/stub.bin"

# `|| true`: keep the output so a headless failure is reported as a diagnostic
# rather than aborting under `set -e` with nothing printed.
raw=$("$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$tmp/proj" asm \
  -import "$tmp/stub.bin" -processor "TMS320C28x:LE:32:default" \
  -scriptPath "$tmp/scripts" -postScript AssembleRoundTrip.java \
  -noanalysis -overwrite 2>&1) || true

out=$(printf '%s\n' "$raw" | sed -n 's/.*AssembleRoundTrip\.java> //p' \
  | sed -E 's/ \(GhidraScript\)[[:space:]]*$//')

printf '%s\n' "$out"

if printf '%s\n' "$out" | grep -q '^ASSEMBLER PASS'; then
  exit 0
fi

echo "--- assembler check did not pass; raw analyzeHeadless output follows ---" >&2
printf '%s\n' "$raw" >&2
exit 1
