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

## Modes and how to run

### Flash-only mode (Phase 1 shape)

The original mode: hand-pick a seed, no analyzed program required.
```
tests/run_fw_parity_bootstrap.sh -Fw <swapped.bin> -Base 0xNNNNN -Seed 0xNNNNN
```
Reaches only code that lives in flash. Ramfunc call targets look OOR and
are dropped -- see `unresolved.tsv` for the list. Useful for a quick sanity
check on a single entry point without setting up analysis.

### Analyzed-program mode (Phase 2)

The full workflow: point at a program that has been through
`SeedFunctions` + `Materialize{Sections,CopyTable}` +
`MarkComponentRegistry`, and the harness chains three extractors in one
headless call:
```
tests/run_fw_parity_bootstrap.sh \
  -SeedsProject <path>/proj.gpr -SeedsProgram <name.bin> \
  [-Base 0xNNNNN] [-MaxSpan 4096]
```

Coverage differences vs flash-only:
- `DumpFwParitySeeds` walks `_c_int00` symbols + `PieVectTableInit` +
  registry-inbound functions, so BFS starts with dozens of seeds instead
  of the one you hand-pick.
- `DumpFwParityImage` dumps every initialized block (flash + materialized
  RAM) as `image.bin` + `image_map.tsv`, so BFS can slice bytes at a
  ramfunc's run address just as it does at a flash address. The
  compressed-copy (LZSS) case works because `MaterializeCopyTable`'s
  decompression is what populates the run region.
- `DumpFwParityFunctions` dumps the analyzer's function set for the
  reachability diff (see below).
- Our-side decode runs against the analyzed program via `-process`
  instead of importing the raw `.bin` flat, so RAM-resident bytes are
  visible without re-copying them into a fresh block.

### Merging both cores of a device

Both CPU1 and CPU2 into one summary:
```
tests/merge_fw_parity_reports.sh \
  cpu1:<cpu1-report_sorted.txt> \
  cpu2:<cpu2-report_sorted.txt>
```
Each row shows which images that WRONG/UNDEF/SKEW key surfaced on. A key
present on both cores is a real spec bug (not an image-specific data
misdecode); a key present on one is worth spot-checking with the sample
address before fixing.

### Reachability diff

In analyzed mode, the report gets a `REACHABILITY` section counting the
BFS-visited entries that our analyzer never bound as a function. Each is
either an inbound call whose site's decoder we're missing (real bug), a
tail-call target we chose not to split (fine), or a false BFS visit past
a decode desync (rare, and the SKEW section flags the desync itself).
`unrooted.tsv` in the OutDir has the full list.

### Region-level parallelism

Add `-Parallel N` to the .ps1 orchestrator to decode a BFS level's regions
across N runspaces concurrently. Requires **PowerShell 7+** (`ForEach-Object
-Parallel`); on Windows PS 5.1 the flag is accepted and warns before falling
back to serial. Measured on a small bootloader: 4-way parallel ~1.25x
faster than serial (small BFS levels amortize poorly); larger sweeps with
deeper call graphs see closer to a 3-4x speedup once level widths grow.

The bash orchestrator remains serial. TI toolchain per-region startup
(~900ms of the ~1s per region) dominates over the actual decoding time; a
follow-up could batch multiple regions into one asm2000 invocation by
emitting multi-section `.asm` with per-region origins, which would help
more than the parallel decode but is a bigger refactor. The two are
compatible.
