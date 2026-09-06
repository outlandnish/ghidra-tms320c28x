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
# ONE DELIBERATE EXCEPTION: a specialised REPEATED form. The repeated program transfers
# (PREAD / PWRITE / XPREAD / XPWRITE in tms320c28x_rpt.sinc) model the C28x program-pointer
# shadow, which the generic wrapper cannot express, so they are top-level constructors that
# claim `rpt_phase=0` and pre-empt the wrapper. That is only safe when the constructor is a
# strict SUBSET of the wrapper's pattern, which needs the wrapper's other two context bits
# too -- so this check demands `rpt_active=1` AND `rptb_flag=0` alongside `rpt_phase=0`.
# Without them the pattern merely OVERLAPS the wrapper's and sleigh reports "constructor
# patterns cannot be distinguished" (or silently resolves the wrong way), which is the same
# class of silent failure this test exists to prevent.
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
# SCOPE: PER LANGUAGE, NOT PER DIRECTORY. The whole problem starts with a `:^instruction`
# wrapper, so a language that has none has nothing to partition and is skipped -- the CLA
# (tms320c28x_cla.slaspec) has no repeat instruction and no rpt_phase context variable at
# all, so demanding the bit on its constructors would be demanding a field that does not
# exist. Each .slaspec's @include tree is resolved and gated on whether it contains a
# wrapper, which keeps this correct automatically when another language is added. A .sinc
# that no .slaspec includes is an error, not a silent skip.
#
# Usage:  bash tests/run_phase_check.sh [module-root]
set -euo pipefail

module="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
lang="$module/data/languages"
[ -d "$lang" ] || { echo "error: no such directory: $lang" >&2; exit 2; }

# Resolve one .slaspec's transitive @include tree (the spec itself first).
spec_tree() {
    local spec="$1" cur inc p
    local -a tree=("$spec") queue=("$spec")
    while [ ${#queue[@]} -gt 0 ]; do
        cur="${queue[0]}"; queue=("${queue[@]:1}")
        while read -r inc; do
            [ -n "$inc" ] || continue
            p="$lang/$inc"
            [ -f "$p" ] || continue
            case " ${tree[*]} " in *" $p "*) continue ;; esac
            tree+=("$p"); queue+=("$p")
        done < <(sed -n 's/^[[:space:]]*@include[[:space:]]*"\([^"]*\)".*/\1/p' "$cur")
    done
    printf '%s\n' "${tree[@]}"
}

check_files=()
seen_files=()
for spec in "$lang"/*.slaspec; do
    mapfile -t tree < <(spec_tree "$spec")
    seen_files+=("${tree[@]}")
    if grep -lqE '^:\^' "${tree[@]}" >/dev/null 2>&1; then
        check_files+=("${tree[@]}")
    else
        echo "skipping $(basename "$spec"): no :^instruction wrapper, so no phase to partition"
    fi
done

# Anything under data/languages that no .slaspec pulls in would escape the check entirely.
for f in "$lang"/*.sinc; do
    case " ${seen_files[*]} " in
        *" $f "*) ;;
        *) echo "error: $(basename "$f") is included by no .slaspec -- it would escape this check" >&2
           exit 2 ;;
    esac
done

[ ${#check_files[@]} -gt 0 ] || { echo "error: no language uses :^instruction wrappers -- refusing to report a vacuous pass" >&2; exit 2; }

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
        } else if (head ~ /rpt_phase[ \t]*=[ \t]*0/) {
            # Specialised repeated form: legal, but only as a strict subset of the wrapper
            # pattern, which needs the wrapper other two context bits as well.
            if (head ~ /rpt_active[ \t]*=[ \t]*1/ && head ~ /rptb_flag[ \t]*=[ \t]*0/) {
                repeated++
            } else {
                printf("  %s:%d: rpt_phase=0 constructor must also carry `rpt_active=1` and `rptb_flag=0`\n      %s\n",
                       shortname, start, first)
                bad++
            }
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
    printf("specialised repeated forms              : %d\n", repeated)
    printf("violations                              : %d\n", bad)
    if (bad > 0) exit 1
}
' "${check_files[@]}" || {
    # Keep the verdict on stdout with the detail lines above it -- interleaving the two
    # across stdout/stderr makes CI logs read out of order.
    echo "FAIL: phase-bit invariant violated (see above)."
    echo "      A constructor without \`& rpt_phase=1\` cannot be wrapped by RPT/RPTB;"
    echo "      \`RPT || <it>\` would execute once instead of N+1 times."
    exit 1
}

echo "PASS: phase-bit invariant holds."
