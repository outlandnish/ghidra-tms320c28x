#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# Static invariant check for the RPT / RPTB phase-bit partition. Needs no Ghidra and no
# SLEIGH compile -- it is pure text over data/languages -- so it runs first and fails fast.
#
# THE INVARIANT. The hardware repeats are modelled by `:^instruction` prefix wrappers
# (data/languages/tms320c28x_rpt.sinc). A wrapper compiles to a variant of EVERY base
# constructor whose pattern is (wrapper_pattern AND base_pattern); if a base imposes no
# context constraint that contradicts the wrapper's, the two overlap and the resolver picks
# the base -- silently making the wrapper a no-op. The fix, as used by every shipped Ghidra
# processor with `:^instruction` (ARM, avr8, 8051, Hexagon), is a phase bit:
#
#   * every top-level `:MNEMONIC` constructor must constrain  rpt_phase=1
#   * the `:^instruction` wrappers must constrain             rpt_phase=0
#
# WHY THIS TEST EXISTS. A new `:MNEMONIC` added without `& rpt_phase=1` decodes perfectly
# and passes every existing fixture. The only symptom is that `RPT || <that instruction>`
# quietly executes once instead of N+1 times -- wrong emulation and a missing loop in the
# decompiler, with nothing failing to point at it. run_disasm_test cannot catch it: the
# listing is correct. Measured cost of the related `noflow` slip on real firmware was 57
# bad decodes, so this class of bug is worth a dedicated guard.
#
# Sub-table definitions (`name: ... is ...`) are not top-level and are exempt.
#
# Usage:  bash tests/run_phase_check.sh [module-root]
set -euo pipefail

module="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
lang="$module/data/languages"
[ -d "$lang" ] || { echo "error: no such directory: $lang" >&2; exit 2; }

awk '
function flush(   head, p) {
    if (buf == "") return
    p = index(buf, "{")
    head = (p > 0) ? substr(buf, 1, p - 1) : buf
    if (isWrapper) {
        wrappers++
        if (head !~ /rpt_phase[ \t]*=[ \t]*0/) {
            printf("  %s:%d: :^instruction wrapper does not constrain rpt_phase=0\n      %s\n",
                   shortname, start, first)
            bad++
        }
    } else if (head ~ /[ \t]is[ \t]/) {
        if (head ~ /rpt_phase[ \t]*=[ \t]*1/) {
            ok++
        } else {
            printf("  %s:%d: top-level constructor missing `& rpt_phase=1`\n      %s\n",
                   shortname, start, first)
            bad++
        }
    }
    buf = ""
}
FNR == 1 {
    flush(); collecting = 0
    shortname = FILENAME
    sub(/^.*\//, "", shortname)
}
/^:/ {
    flush()
    buf = $0; first = $0; start = FNR; span = 0
    isWrapper = ($0 ~ /^:\^/)
    collecting = 1
    if (index(buf, "{")) { flush(); collecting = 0 }
    next
}
collecting {
    buf = buf " " $0
    span++
    # A constructor head never runs more than a few lines before its semantic body.
    if (index(buf, "{") || span > 6) { flush(); collecting = 0 }
    next
}
END {
    flush()
    printf("top-level constructors with rpt_phase=1 : %d\n", ok)
    printf(":^instruction wrappers                  : %d\n", wrappers)
    printf("violations                              : %d\n", bad)
    if (bad > 0) exit 1
}
' "$lang"/*.sinc "$lang"/*.slaspec || {
    # Keep the verdict on stdout with the detail lines above it -- interleaving the two
    # across stdout/stderr makes CI logs read out of order.
    echo "FAIL: phase-bit invariant violated (see above)."
    echo "      A constructor without \`& rpt_phase=1\` cannot be wrapped by RPT/RPTB;"
    echo "      \`RPT || <it>\` would execute once instead of N+1 times."
    exit 1
}

echo "PASS: phase-bit invariant holds."
