#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# Audit the C28x SLEIGH spec for two classes of missing flag semantics:
#
#   PASS 1 (issue #90 -- shipped): ALU constructors that WRITE ACC/AX with an
#     arithmetic operator but WRITE NO FLAG at all. Original hole was 32
#     constructors; guard against re-introducing it.
#
#   PASS 2 (issue #93): ALU constructors that WRITE ACC and SET $(V) but
#     DON'T update OVC. OVC is the 6-bit signed overflow counter (ST0[15:10])
#     that TI's math libraries read via SAT ACC. Missing OVC updates make
#     saturation-aware code loop forever, same class as the SUBB fill-loop
#     hole that motivated #90.
#
#   PASS 3 (issue #95): MAC-family and add-with-carry / sub-with-borrow
#     constructors named in SPRU430F Table 2-5 as OVC-affecting, whose
#     bodies write ACC but do NOT touch OVC. Distinct from pass 2 because
#     these can (and did) set only N/Z without ever writing $(V), which
#     kept pass 2 blind to them -- the SBBU hole was exactly this shape.
#
#   PASS 4: V overwrites. V is STICKY -- SPRU430F: "if an overflow occurs, V is
#     set; otherwise V is not affected" -- and is cleared only by a COND test
#     of it (the CC/CC8 NOV/OV rows) and a handful of ops that say so. A plain
#     `$(V) = scarry(...)` clears a V an earlier instruction set, so a 64-bit
#     add/compare chain (... ; CMP64) or a later SB ...,OV misses the overflow.
#     Write `$(V) = $(V) | ovf;`, or annotate the line `# flag-audit-v: <why>`
#     when SPRU430F documents that this op clears V.
#
#   PASS 5: OVM saturation. SPRU430F 2.3: with OVM=1 an ACC overflow does
#     not count in OVC; the CPU saturates ACC instead. So every
#     applyOvcSigned(ovf, X) must be followed by applyOvmSaturateSigned(ovf, X)
#     in the same body. Opt out with `# flag-audit-ovm: none`.
#
# Exit non-zero on any un-annotated candidate. To exempt a constructor:
#   # flag-audit: none       -- flagless BY SPRU430F (pass 1 opt-out)
#   # flag-audit-ovc: none   -- V-writer that spec explicitly leaves OVC alone
#                              (e.g. CMP/CMPL, or the non-ACC OVC-affecting ops
#                              where OVC is not touched per the general rule
#                              "OVC is not affected by overflows in registers
#                              other than ACC" -- SPRU430F 2.3)
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANG = os.path.join(ROOT, 'data', 'languages')

# Match $(X) = ... but NOT $(X) == ... (which is a READ via equality).
FLAG_WRITE = re.compile(
    r'\$\((?:N|Z|C|V|OVC|TC|SXM|OVM)\)\s*=(?!=)|setNZ\d*\s*\(|setflags')
V_WRITE = re.compile(r'\$\(V\)\s*=(?!=)')
OVC_WRITE = re.compile(
    r'\bOVC\s*=|applyOvcSigned\s*\(|applyOvcUnsigned\s*\(|'
    r'applyOvcuBorrow\s*\(')
# Sub-table alias names for the accumulator halves. `ACCreg`, `AXb0`, `AXb4`
# resolve to ACC/AH/AL at Sleigh-compile time (see tms320c28x.sinc lines
# 341/354-355/358-359). A DEST regex that omits them silently exempts every
# shift, MPY, and MPYB constructor -- exactly the hole that let issue #104
# open. Keep this alternation in sync when new attach-variables aliases land.
ACC_DEST = re.compile(r'(?:^|[{;])\s*(?:ACC|ACCreg)\s*=', re.M)
P_DEST   = re.compile(r'(?:^|[{;])\s*P\s*=', re.M)
DEST = re.compile(
    r'(?:^|[{;])\s*(ACC|AH|AL|AX|ACCreg|AXb0|AXb4)\s*=', re.M)
ARITH = re.compile(r'=\s*[^;]*[-+&|^]|<<|>>|\w\s*\*\s*\w')
OPT_OUT = re.compile(r'#\s*flag-audit:\s*none')
OPT_OUT_OVC = re.compile(r'#\s*flag-audit-ovc:\s*none')
# Pass 4: a V write that is neither sticky (`$(V) | ...`) nor a set-only `= 1`.
V_OVERWRITE = re.compile(r'\$\(V\)\s*=(?!=)(?!\s*(?:\$\(V\)\s*\||1\s*;))')
OPT_OUT_V = re.compile(r'#\s*flag-audit-v:')
CC_ROW = re.compile(r'^CC8?:')
OVC_SIGNED = re.compile(r'applyOvcSigned\(\s*\w+\s*,\s*(\w+)\s*\)')
OPT_OUT_OVM = re.compile(r'#\s*flag-audit-ovm:\s*none')

# Mnemonics whose defining act is an ALU-style compute. Extended as new
# instructions with flag semantics are added; the guiding rule is "SPRU430F
# documents flag effects for it".
ALU = set("""
ADD ADDB ADDU ADDL ADDCU ADDCL SUB SUBB SUBU SUBL SUBBL SUBCU SUBCUL SBBU
AND OR XOR NOT NEG NEGL ABS ABSTC INC DEC CMP CMPL CMPB TEST
ASR ASR64 ASRL LSL LSL64 LSLL LSR LSR64 LSRL SFR ROL ROR
MOV MOVL MOVU MOVB MOVH ZALR SAT SAT64 NORM FLIP CSB
MAC MPY MPYA MPYB MPYS MPYU MPYXU
QMPYL QMPYUL QMPYXUL QMPYAL QMPYSL
IMPYL IMPYXUL IMPYAL
DMAC QMACL IMACL
ADDUL SUBUL
""".split())

# SPRU430F Table 2-5 subset that this repo currently models and whose ACC-
# writing body must therefore touch OVC. Deliberately excludes non-ACC
# destinations (INC/DEC/ADDUL P/SUBUL P) -- Table 2-5 lists those but the
# general rule "OVC is not affected by overflows in registers other than
# ACC" contradicts, and no firmware witness has been checked in yet
# (issue #98 tracks the resolution).
OVC_REQUIRED = set("""
ADDCL ADDCU ADDU MOVA MOVAD MOVS SBBU SQRA SQRS XMAC XMACD
QMPYAL QMPYSL IMPYAL MPYA
DMAC QMACL IMACL
ADDUL SUBUL
""".split())
# Members of OVC_REQUIRED that can legally write to P (not just ACC). SPRU430F
# §2.3 says "OVC unaffected by non-ACC destinations" as a GENERAL rule, but the
# individual instruction pages carve out ADDUL P and SUBUL P as OVCU-affected
# (SPRU430F ch. 6, resolved via issue #98). Pass 3 accepts either ACC or P as
# the destination for these mnemonics.
OVC_P_DEST_OK = set("ADDUL SUBUL".split())


def parse_constructors(path):
    """Yield (mnemonic, line_no, head_line, body_text, preamble) per ctor.

    `preamble` is the contiguous block of `#` comment lines immediately above
    the constructor -- opt-out markers can live there as well as on the head.
    """
    lines = open(path).read().split('\n')
    i = 0
    while i < len(lines):
        m = re.match(r'^:([A-Z][A-Z0-9_.]*)\s', lines[i])
        if not m:
            i += 1
            continue
        mn = m.group(1)
        # walk back over the leading comment block
        pre_start = i
        while pre_start > 0 and lines[pre_start - 1].lstrip().startswith('#'):
            pre_start -= 1
        preamble = '\n'.join(lines[pre_start:i])
        depth, chunk, j, started = 0, [], i, False
        while j < len(lines):
            chunk.append(lines[j])
            depth += lines[j].count('{') - lines[j].count('}')
            if '{' in lines[j]:
                started = True
            if started and depth <= 0:
                break
            j += 1
        text = '\n'.join(chunk)
        head = chunk[0]
        body = text[text.find('{'):] if '{' in text else ''
        yield mn, i + 1, head, body, preamble
        i = j + 1


def audit():
    """Return (pass1_hits, pass2_hits, pass3_hits, pass5_hits, scanned)."""
    pass1 = []
    pass2 = []
    pass3 = []
    pass5 = []
    scanned = 0
    paths = sorted(glob.glob(os.path.join(LANG, '*.sinc'))) + \
        sorted(glob.glob(os.path.join(LANG, '*.slaspec')))
    for path in paths:
        for mn, ln, head, body, pre in parse_constructors(path):
            scanned += 1
            if mn not in ALU and mn not in OVC_REQUIRED:
                continue
            has_flag = bool(FLAG_WRITE.search(body))
            has_v = bool(V_WRITE.search(body))
            has_ovc = bool(OVC_WRITE.search(body))
            writes_acc = bool(ACC_DEST.search(body))
            writes_p   = bool(P_DEST.search(body))
            writes_dest = bool(DEST.search(body))
            has_arith = bool(ARITH.search(body))
            fname = os.path.basename(path)
            head_s = head.strip()
            hp = head + '\n' + pre  # search head + preceding comment block
            if mn in ALU and not has_flag and writes_dest and has_arith:
                if not OPT_OUT.search(hp):
                    pass1.append((mn, fname, ln, head_s))
            # Pass 2: V-writer on ACC that does not touch OVC.
            if has_v and writes_acc and not has_ovc:
                if not OPT_OUT_OVC.search(hp):
                    pass2.append((mn, fname, ln, head_s))
            # Pass 3: Table 2-5 OVC-required mnemonic whose ACC-writing body
            # doesn't touch OVC. Distinct from pass 2 because these bodies
            # can pass pass 1 (they write N/Z) and pass 2 (they don't set V)
            # while still leaving OVC stale. Members of OVC_P_DEST_OK may
            # also legally write P instead of ACC.
            dest_ok = (writes_acc or
                       (mn in OVC_P_DEST_OK and writes_p))
            if mn in OVC_REQUIRED and dest_ok and not has_ovc:
                if not OPT_OUT_OVC.search(hp):
                    pass3.append((mn, fname, ln, head_s))
            # Pass 5: a signed OVC update with no OVM saturation of the same value.
            for m in OVC_SIGNED.finditer(body):
                sat = re.compile(r'applyOvmSaturateSigned\(\s*\w+\s*,\s*%s\s*\)'
                                 % re.escape(m.group(1)))
                if not sat.search(body, m.end()) and not OPT_OUT_OVM.search(hp):
                    pass5.append((mn, fname, ln, head_s))
    return pass1, pass2, pass3, pass5, scanned


def audit_v():
    """Pass 4: line-level, so it also sees macros and sub-tables."""
    hits = []
    for path in sorted(glob.glob(os.path.join(LANG, '*.sinc'))):
        for ln, line in enumerate(open(path).read().split('\n'), 1):
            if CC_ROW.match(line) or OPT_OUT_V.search(line):
                continue
            code = line.split('#', 1)[0]
            if V_OVERWRITE.search(code):
                hits.append(('V', os.path.basename(path), ln, line.strip()))
    return hits


def report(hits, title, remedy):
    print(f'flag_audit: FAIL -- {title}')
    print(remedy + '\n')
    for mn, f, ln, head in hits:
        print(f'  {mn:6s} {f}:{ln}\n    {head[:100]}')
    print(f'\n{len(hits)} candidate(s).')


def main():
    pass1, pass2, pass3, pass5, scanned = audit()
    pass4 = audit_v()
    if not pass1 and not pass2 and not pass3 and not pass4 and not pass5:
        print(f'flag_audit: OK ({scanned} constructors scanned, '
              f'0 pass-1, 0 pass-2, 0 pass-3, 0 pass-4, 0 pass-5 candidates)')
        return 0
    if pass1:
        report(
            pass1,
            'ALU-family constructors write ACC/AX with no flag write.',
            "If the instruction is flagless BY SPRU430F, add `# flag-audit: "
            "none`\non the constructor's opening line; otherwise fix the "
            "missing flag semantics.")
        print()
    if pass2:
        report(
            pass2,
            'ALU-family constructors write ACC and set $(V) but do NOT touch '
            'OVC.',
            "Add applyOvcSigned(ovf, ACC) / applyOvcUnsigned() after the V write; "
            "OR add\n`# flag-audit-ovc: none` if SPRU430F Table 2-5 explicitly"
            " excludes the\ninstruction from OVC accounting (e.g. CMP, CMPL, "
            "or non-ACC-destination forms).")
        print()
    if pass3:
        report(
            pass3,
            'SPRU430F Table 2-5 OVC-affecting instructions write ACC but do '
            'NOT touch OVC.',
            "Add applyOvcSigned(ovf, ACC) / applyOvcUnsigned() on the ACC += P "
            "(or ACC -= P)\nstep; OR add `# flag-audit-ovc: none` if SPRU430F"
            " explicitly excludes\nthe form (rare -- Table 2-5 is the source"
            " of truth here).")
        print()
    if pass4:
        report(
            pass4,
            'V written without keeping its previous value (V is sticky).',
            "Write `local ovf:1 = ...; $(V) = $(V) | ovf;` and pass `ovf` to "
            "applyOvcSigned /\napplyOvmSaturate*; OR annotate the line "
            "`# flag-audit-v: <why>` if SPRU430F says\nthis op clears V.")
        print()
    if pass5:
        report(
            pass5,
            'Signed OVC update with no OVM saturation of the same value.',
            "Add applyOvmSaturateSigned(ovf, X) right after applyOvcSigned(ovf, "
            "X), before\nsetNZ32; OR add `# flag-audit-ovm: none` if SPRU430F "
            "gives the op no OVM row.")
    print(f'\n{scanned} constructors scanned.')
    return 1


if __name__ == '__main__':
    sys.exit(main())
