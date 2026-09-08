#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# Audit the C28x SLEIGH spec for ALU constructors that compute a result but set no flags.
# Guards against re-introducing the class fixed by issue #90 (32 constructors across the
# ADD/SUB/MOV/ADDL/SUBL/MOVB/ABS/ADDUL/ASRL/LSLL/LSRL/MAC/MPYS/NORM/QMPYL/SFR/SUBCU/
# SUBCUL/ZALR families -- see the issue body for the audit method).
#
# Exit non-zero on any un-annotated candidate. Constructors whose family is FLAGLESS BY SPRU430F
# (there are none in this batch, but future ALU adds might qualify) can be exempted by adding a
# `# flag-audit: none` end-of-line comment to the constructor's opening line.
#
# Strategy: scan every top-level constructor for a mnemonic in ALU below; parse the p-code body
# between the outer braces; flag ones that WRITE to ACC/AX with arithmetic and DON'T write a
# flag ($(N)/$(Z)/$(C)/$(V)/setNZ*). Deliberately narrow: MOV loc16 forms, plain register loads
# and control-register moves are NOT alu operations and stay out of the ALU set.
import collections
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANG = os.path.join(ROOT, 'data', 'languages')

# Any assignment to N/Z/C/V/OVC/TC (bare or via $()), or a setNZ macro.
FLAG_WRITE = re.compile(
    r'\$\((?:N|Z|C|V|OVC|TC|SXM|OVM)\)\s*=|setNZ\d*\s*\(|setflags')
DEST = re.compile(r'(?:^|[{;])\s*(ACC|AH|AL|AX)\s*=', re.M)
ARITH = re.compile(r'=\s*[^;]*[-+&|^]|<<|>>')
OPT_OUT = re.compile(r'#\s*flag-audit:\s*none')

# Mnemonics whose defining act is an ALU-style compute. Extended as new instructions with
# flag semantics are added; the guiding rule is "SPRU430F documents flag effects for it".
ALU = set("""
ADD ADDB ADDU ADDL ADDCU SUB SUBB SUBU SUBL SUBBL SUBCU SUBCUL SBBU
AND OR XOR NOT NEG NEGL ABS ABSTC INC DEC CMP CMPL CMPB TEST
ASR ASRL LSL LSLL LSR LSRL SFR SBF ROL ROR
MOV MOVL MOVU MOVB MOVH ZALR SAT SAT64 NORM FLIP CSB
MAC MPY MPYB MPYU MPYS QMPYL IMPYL ADDUL
""".split())


def parse_constructors(path):
    """Yield (mnemonic, line_no, head_line, body_text) for each top-level constructor."""
    lines = open(path).read().split('\n')
    i = 0
    while i < len(lines):
        m = re.match(r'^:([A-Z][A-Z0-9_.]*)\s', lines[i])
        if not m:
            i += 1
            continue
        mn = m.group(1)
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
        yield mn, i + 1, head, body
        i = j + 1


def audit():
    hits = []
    scanned = 0
    for path in sorted(glob.glob(os.path.join(LANG, '*.sinc'))) + \
                sorted(glob.glob(os.path.join(LANG, '*.slaspec'))):
        for mn, ln, head, body in parse_constructors(path):
            scanned += 1
            if mn not in ALU:
                continue
            if OPT_OUT.search(head):
                continue
            if FLAG_WRITE.search(body):
                continue
            if not (DEST.search(body) and ARITH.search(body)):
                continue
            hits.append((mn, os.path.basename(path), ln, head.strip()))
    return hits, scanned


def main():
    hits, scanned = audit()
    if not hits:
        print(f'flag_audit: OK ({scanned} constructors scanned, 0 candidates)')
        return 0
    print('flag_audit: FAIL -- ALU-family constructors write ACC/AX with no flag write.')
    print('If the instruction is flagless BY SPRU430F, add `# flag-audit: none` on the')
    print('constructor\'s opening line; otherwise fix the missing flag semantics.\n')
    for mn, f, ln, head in hits:
        print(f'  {mn:6s} {f}:{ln}\n    {head[:100]}')
    print(f'\n{len(hits)} candidate(s); {scanned} constructors scanned.')
    return 1


if __name__ == '__main__':
    sys.exit(main())
