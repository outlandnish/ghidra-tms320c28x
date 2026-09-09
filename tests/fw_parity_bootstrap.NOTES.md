# fw-parity bootstrap — findings from the initial sweep

The bootstrap harness ([run_fw_parity_bootstrap.sh](run_fw_parity_bootstrap.sh)
/ [.ps1](run_fw_parity_bootstrap.ps1)) walks a firmware image's call graph
using dis2000 as both the disassembler and the ground truth, so bounds are
NEVER derived from our SLEIGH. Gaps our own analyzer's function boundaries
would hide (wrong-length constructors truncating a function, UNDEF cutting
flow, mis-modeled branches sending flow into data) become visible.

## Initial CPU2 sweep (base 0xb0000, single CRT seed, MaxSpan 2048)

87 regions BFS-discovered, 35,736 TI-decoded instructions, 34,367 operand-
formatting diffs (mostly cosmetic — decimal vs hex, `@` register-direct
marker, absolute vs relative branch targets). Real gaps:

### WRONG mnemonic (decode bugs — MUST fix)

| Count | TI → ours | Sample word |
|---|---|---|
| 6 | `MOV` → `MOVZ` | 0xb0f1e (TI: `MOV AR7, *-SP[62]`; ours: `MOVZ AR7,*-SP[0x3e]`) |

The `AR7, *-SP[62]` operand form makes this a stack-local direct-mode MOV that
our constructor decodes as MOVZ. Likely an opcode-mask precedence problem
between the MOV and MOVZ constructors on the AR7 destination.

### UNDEF (missing constructors, ranked by frequency)

| Count | TI mnem | Sample word |
|---|---|---|
| 5 | MOV   | 0xb1157 |
| 4 | LCR   | 0xb306e |
| 4 | ADD   | 0xb7eff |
| 4 | SBRK  | 0xb1529 |
| 3 | SUB   | 0xb57ac |
| 3 | FFC   | 0xb150f |
| 3 | ADRK  | 0xb2122 |
| 2 | BANZ  | 0xb14b3 |
| 2 | RPT   | 0xb1094 |
| 2 | OR    | 0xb102e |
| 2 | MOVIZ | 0xb0fec |
| 1 | TBIT  | 0xb436e |
| 1 | MOVB  | 0xb0f5a |
| 1 | MOVZ  | 0xb7e4e |
| 1 | MOVXI | 0xb12f9 |
| 1 | LB    | 0xb43bc |
| 1 | LSL   | 0xb6d36 |
| 1 | LC    | 0xb7869 |

The RPT / BANZ hits are the most surprising -- both are common constructors
we thought were fully covered, so those two encodings are probably narrow
addressing-mode variants (rather than whole missing constructors).

### SKEW (length disagreement — constructor consumed wrong # of words)

| Count | TI mnem | Sample word |
|---|---|---|
| 2 | TRAP | 0xb14b5 |
| 1 | ADDB | 0xb43be |
| 1 | SB   | 0xb1391 |
| 1 | LC   | 0xb786b |

Every length skew desyncs the sweep for a small window after it: TI stays on
the right start-word, we don't, and every subsequent instruction reads as
WRONG or SKEW until the next place our alignment happens to match theirs
again. The TRAP skews are the most interesting -- our TRAP is single-word, so
we may be seeing a 2-word TRAP encoding TI decodes but we don't.

## Interpreting the numbers

- **35,684 / 35,736 = 99.85% mnemonic agreement.** The audits over the past
  several PRs (issues #106 / #108 / #110 / #112 / #114 / #118) drove this
  number up; a fresh sweep should re-verify it hasn't regressed.
- **operand-text diffs (34,367) are mostly noise.** They read as scary in the
  summary line but reflect that our rendering never matched TI's byte-for-
  byte (hex vs decimal, `@` marker, comma spacing). Real operand-level bugs
  hide in this bucket -- eyeball the per-region side-by-side if a particular
  constructor is under suspicion.
- **The BFS is single-seed.** BFS from `_c_int00` covers only what the call
  graph statically reaches. Interrupt handlers rooted from the PIE vector
  table's flash initializer, and dispatch-registry targets, are not
  discovered by BFS from CRT alone -- use `DumpFwParitySeeds.java` on a
  fully-analyzed image and pass `-Seeds seeds.tsv` to cover those.

## Prioritization

The WRONG hits are the only bugs that will silently deceive the decompiler
(a plausible-but-different mnemonic never fails obviously). The UNDEF hits
are visible in every listing they touch. The SKEW hits are the worst per
occurrence -- one bad length poisons a window of decode until the alignment
recovers -- but there are few of them.

If the next fix batch groups by these buckets: WRONG first (6 sites, one
constructor), then TRAP / SB / ADDB / LC skew (5 sites, at most 4
constructors), then the top-frequency UNDEFs (MOV, LCR, ADD, SBRK, SUB,
FFC).
