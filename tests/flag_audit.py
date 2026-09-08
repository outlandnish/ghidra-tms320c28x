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
ACC_DEST = re.compile(r'(?:^|[{;])\s*ACC\s*=', re.M)
P_DEST   = re.compile(r'(?:^|[{;])\s*P\s*=', re.M)
DEST = re.compile(r'(?:^|[{;])\s*(ACC|AH|AL|AX)\s*=', re.M)
ARITH = re.compile(r'=\s*[^;]*[-+&|^]|<<|>>|\w\s*\*\s*\w')
OPT_OUT = re.compile(r'#\s*flag-audit:\s*none')
OPT_OUT_OVC = re.compile(r'#\s*flag-audit-ovc:\s*none')

# Mnemonics whose defining act is an ALU-style compute. Extended as new
# instructions with flag semantics are added; the guiding rule is "SPRU430F
# documents flag effects for it".
ALU = set("""
ADD ADDB ADDU ADDL ADDCU ADDCL SUB SUBB SUBU SUBL SUBBL SUBCU SUBCUL SBBU
AND OR XOR NOT NEG NEGL ABS ABSTC INC DEC CMP CMPL CMPB TEST
ASR ASRL LSL LSLL LSR LSRL SFR SBF ROL ROR
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
ADDCL ADDCU MOVA MOVAD MOVS SBBU SQRA SQRS XMAC XMACD
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
    """Return (pass1_hits, pass2_hits, pass3_hits, scanned)."""
    pass1 = []
    pass2 = []
    pass3 = []
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
    return pass1, pass2, pass3, scanned


def report(hits, title, remedy):
    print(f'flag_audit: FAIL -- {title}')
    print(remedy + '\n')
    for mn, f, ln, head in hits:
        print(f'  {mn:6s} {f}:{ln}\n    {head[:100]}')
    print(f'\n{len(hits)} candidate(s).')


def main():
    pass1, pass2, pass3, scanned = audit()
    if not pass1 and not pass2 and not pass3:
        print(f'flag_audit: OK ({scanned} constructors scanned, '
              f'0 pass-1, 0 pass-2, 0 pass-3 candidates)')
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
            "Add applyOvcSigned(ACC) / applyOvcUnsigned() after the V write; "
            "OR add\n`# flag-audit-ovc: none` if SPRU430F Table 2-5 explicitly"
            " excludes the\ninstruction from OVC accounting (e.g. CMP, CMPL, "
            "or non-ACC-destination forms).")
        print()
    if pass3:
        report(
            pass3,
            'SPRU430F Table 2-5 OVC-affecting instructions write ACC but do '
            'NOT touch OVC.',
            "Add applyOvcSigned(ACC) / applyOvcUnsigned() on the ACC += P "
            "(or ACC -= P)\nstep; OR add `# flag-audit-ovc: none` if SPRU430F"
            " explicitly excludes\nthe form (rare -- Table 2-5 is the source"
            " of truth here).")
    print(f'\n{scanned} constructors scanned.')
    return 1


if __name__ == '__main__':
    sys.exit(main())
