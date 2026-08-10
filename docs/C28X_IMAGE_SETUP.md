# Setting up a headerless C28x firmware image for analysis

The full recipe to turn a raw, byte-swapped C28x flash dump into a fully analyzable Ghidra
program — from import through recovering the RAM-resident code that the app copies out of flash
at startup. Every step is a script in the **TMS320C28x** Script-Manager category.

## Pipeline

| # | Step | What it does |
|---|------|--------------|
| 0 | **Import + set base** | Load the raw `.bin` as `TMS320C28x:LE:32:default` (F28377D) or `…:f2812`. Set the image base to the flash word address (e.g. `0x82000` for a DIR, `0x88000` for a PMR). See below on the byte-swap. |
| 1 | `SetupF28377D.java` (or `SetupF2812.java`) | Map the device memory — peripheral MMIO frames **and the on-chip RAM regions**, split into their datasheet banks (`M0`/`M1`, `LS0`…`LS5`, `D0`/`D1`, `GS0-15`, CLA/CPU MSGRAMs) with correct perms (SARAM → **RWX** since ramfuncs run there; ROM → RX; message RAM → RW). Also maps the DCAN `CANA`/`CANB` message RAM (`0x49000`/`0x4b000`) and (CPU1) the uPP message RAM. Mapping RAM is what lets calls into it resolve later. **Pass the CPU as the script arg: `CPU1` for PMR / bootloader (`*bl`) / boot-updater (`*bu`), `CPU2` for DIR** — it selects the CPU1-only peripheral set (UPP/XBAR/USBA/DEV_CFG). |
| 2 | `SeedFunctions.java` | Recover functions from the bytes (call targets + prologues) and add call-site→target refs. |
| 3 | `MarkJumpTables.java`, `MarkDataTables.java` | Mark switch/pointer tables and float-constant pools as data so they stop decoding as garbage. |
| 4 | **`MaterializeSections.java`** (or **`MaterializeCopyTable.java`**) | Copy the flash **load images** into their RAM **run** addresses so the RAM-resident code/data becomes real. Which one depends on the startup copy mechanism — see Step 4 / 4b and the decision note. |
| 5 | **`FinalizeRamfuncs.java`** | Post-analysis cleanup of the materialized ramfuncs (rebuild bodies; repair flash callers). Run it **after** analysis has settled. See below. |
| 6 | `RetypeWideMemory.java` | Retype 32/64-bit memory operands to kill `CONCAT22`/`CONCAT44` in the decompiler. |
| 7 | **Residual-mark cleanup + verify** (inline recipe) | Sweep the leftover `Bad Instruction` marks and confirm the result against a known-good image. See Step 7. |

### The byte-swap

Some C28x flash images ship byte-swapped (byte pairs reversed relative to the on-chip word
layout). If yours is one of them, produce a swapped `.bin` first, import THAT, and set the
base. In this `wordsize=2` space Ghidra's `Address.getOffset()` returns a **byte** offset
(= word × 2) while TI's `dis2000` prints **word** addresses — divide by 2 when comparing.
Scripts that walk the listing already account for this.

## Step 4 — MaterializeSections

**Why.** On TI-RTS C28x images, time-critical code (`.ramfunc` — flash program/erase, motor-control
inner loops) and initialized data (`.cinit`) live in **flash at a LOAD address** and are copied to
**RAM at a RUN address by the application's own C-runtime startup** (not the bootloader). In a static
flash-only dump the RAM run regions are uninitialized, so an `LCR 0x9669`-into-RAM hits "Disassembly
not permitted within uninitialized memory block" and every RAM-resident function is invisible, with
its (often 100+) flash callers dangling. Because the copy is done by the app's own startup, the
flash dump already contains everything needed — you just have to replay the copy.

**How it finds the copies.** A startup dispatcher calls a tight word-memcpy (`memcpyWords(count,
dst, src)`) once per section with constant `(size, RAM-run, flash-load)` args. The script does a
forward constant-propagation pass, snapshots the live constants at each call, and forms
`(size, run, load)` triples where `load` is in the flash image (fully initialized), `run` is mapped
RAM above the M0/M1 scratch (`≥ 0x800`), and `size` is a non-pointer count. It groups triples by the
**callee** (robust: the call reference is always present, unlike function binding, which analysis
applies non-deterministically) and picks the copy routine by **disjoint-section count + presence of a
CODE section** — real sections have non-overlapping runs and only the ramfunc-copier moves code, so a
scratch-buffer helper (many copies to one run) and coincidental false-positives lose.

**What it does per section.** Convert the overlapped RAM block(s) to initialized and `setBytes` the
flash load-image in, **splitting the write at the LS0-5 / D0-1 seam at word `0xB000`**. A CODE
section (run region has incoming CALL refs from flash) is marked executable, then each CALL-target is
disassembled (all first, then bound — a single interleaved pass stubs ~half the functions) and turned
into a function. The section's **flash LOAD image** is then marked as an `undefined2[]` array and its
phantom duplicate functions dropped — the load image is byte-identical to the RAM run image but is
never executed in place (its only xref is the copy-source pointer), so leaving it decoded produces
confusing duplicates (e.g. `FUN_00082f2c` mirroring the ramfunc at `0x9300`).

Properties: `-Dc28x.mat.dryRun`, `-Dc28x.mat.copyfn=0xWORD` (force the copy routine),
`-Dc28x.mat.minSites`, `-Dc28x.mat.disasm`. Additive and idempotent; never overwrites a user symbol.

Validated on dir_26_65_2: copy routine `memcpyWords`, 5 disjoint sections incl `.ramfunc`
`0x82f2c→0x9300` (0x260c words, CODE, 59 targets) + `.cinit` `0xb9d00→0xdf80` (DATA); RAM == flash
byte-for-byte including across the LS→D seam.

## Step 4b — MaterializeCopyTable (newer compressed `__TI_auto_init` copy-table images)

Newer C28x builds (e.g. the **2026 DIR / CPU2** image) copy `.ramfunc`/`.cinit` via a **compressed
copy table** instead of the memcpy-with-constant-args startup MaterializeSections reads. The tell:
MaterializeSections prints **"NO copy routine found"** yet the image still has hundreds of flash
`LCR`s into uninitialized RAM (a real ramfunc). Use `MaterializeCopyTable.java`.

The table (auto-detected by a structural scan, or forced with `-Dc28x.ct.base=0xWORD`) is a run of
6-word records `{size:u32, load:u32, run:u32}` terminated by an all-`0xffffffff` record:

- `size != 0` → **raw copy**: `size` words from flash `load` to RAM `run`.
- `size == 0` → **handler dispatch**: `*load` is a handler index; the payload starts at `load+1`.
  The script implements the TI **LZSS** handler: read a 16-bit control word (LSB first); for each bit,
  `1` = copy one literal word from src, `0` = back-reference word `W` with `len=(W&0xf)+2`
  (if `len==0x11`, `len = nextWord + 0x11`) and `off=(W>>4)&0xfff` (if `off==0xfff`, END) — copy
  `len` words from `dest-1-off`.

It writes each section into RAM (splitting across the LS/D seam), then **classifies each run region
by incoming CALL/JUMP references, not by address**: a run is code iff at least one address in it has
a call/jump ref (from a flash `LCR` or another ramfunc). Code runs are disassembled at every
call/jump target and bound to functions; **data runs — float const pools or `.cinit` copied into LS/D
RAM with zero code refs — are marked `undefined2[]`**. This matters: a naive address-range rule
(`0x8000 ≤ run < 0xc000 ⇒ code`) disassembles an IEEE-754 pool copied to e.g. `run 0x9200` and
produces `halt_baddata`; classifying by refs avoids it and also picks up **M0-RAM** code runs
(`run < 0x8000`, e.g. an ISR block at `0x122`) that the range rule skips.

**Flash-tail marking is position-aware.** The copy table + const pools + load images are marked as
`undefined2[]` so they stop decoding as phantom functions. When the table sits near flash-**end** (all
load images clustered after it — e.g. dir2026 @`0xb7752`), a single blanket `[table … flash-end]`
mark is used. But when the table sits **early** (e.g. dir_pedal_dit0 @`0x81f94`, client_dir @`0x81f76`)
the bulk of executable flash lies **between** the table and the tail load images, so a blanket mark
would erase it — the script detects this (table not in the last ⅛ of flash) and instead marks only the
table extent + each record's own load-image extent. `-Dc28x.ct.noTailData=true` disables all marking.
Run FinalizeRamfuncs afterwards. Detection is conservative (terminator + valid handler index), so on a
memcpy-const image (e.g. 2026/client **PMR / CPU1**) it finds nothing and you fall back to
MaterializeSections.

Two on-disk copy-table **variants** have been seen; both are auto-detected as "compressed copy
table" images by MaterializeSections printing "NO copy routine found":

- **LZSS `{size,load,run}`, 6-word records** (the form above): 2026 DIR, dir_pedal_dit0, client_dir.
- **RAW `{load,run,size,flags}`, 8-word records**, all raw copies (no LZSS handler, so
  `MaterializeCopyTable`'s handler-requiring detector skips it): dir_can_dit1. Materialize inline by
  walking the 8-word records (terminated by `0xffffffff`) and copying `size` words `load→run`, then
  applying the same ref-based run classification. (Generalizing the detector to this variant is a
  TODO.)

Validated on dir2026 (CPU2): copy table @ `0xb7752`, 156 flash callers resolved, 434→2 markers.
Validated on dir_pedal_dit0 / client_dir (CPU2, early table @`0x81f94`/`0x81f76`): 4 code + 2 data
runs classified, **0** residual markers.

### When neither materializer auto-detects the copy

If MaterializeSections prints "NO copy routine found" **and** MaterializeCopyTable prints "copy-table
not found", but the image still has flash `LCR`s into uninitialized RAM, work down this list:

1. **Single-section image (bootloaders / boot-updaters).** The copier is often a general `memcpyWords`
   called once with constant `(size, run, load)` — MaterializeSections needs ≥2 disjoint sections by
   default. Re-run with **`-Dc28x.mat.minSites=1`** (and `-Dc28x.mat.copyfn=0xWORD` if the routine is
   ambiguous). `client_pmrbl`/`pmrbu` copy a single flash-write `.ramfunc` to D0 RAM (`run ~0xb101`)
   this way; the memcpy itself lives in the device-init function, not a section-copy dispatcher.
2. **RAW `{load,run,size,flags}` 8-word table** (no LZSS handler → the auto-detector skips it): locate
   it by scanning flash for a known RAM *run* address as a 32-bit value; the surrounding words are the
   `{load,run,size}` triple. Materialize inline (copy `size` words `load→run`) then apply the same
   ref-based run classification. (`dir_can_dit1`.)
3. **It may be DEAD CODE, not a live section.** Before assuming a materialization gap, prove the run
   region is actually used: (a) does anything **write/copy** into it (any write/data ref into the run
   range)? (b) is the flash code that references it **reachable from `_c_int00`** (call-graph BFS —
   and check indirect reach: stored function-pointers to it, jump-table entries)? If it is
   **unreferenced AND never written**, it is orphaned/dead flash, not a section to materialize. The
   `client_pmrbl` LS-RAM references (`0x8000-0x8fff`, 5 functions at `0x826bd-0x82ad7`) turned out to be
   exactly this — zero refs, unreachable, no copy targets `0x8000` (all 4 real copies go to D0). Don't
   chase it.

### Bootloader / boot-updater images (pmrbl, pmrbu) — LS-RAM section NOT auto-materialized

The small PM-family `*bl`/`*bu` images (`client_pmrbl` @0x82000, `client_pmrbu` @0x88000) copy a
**flash-write ramfunc to D0 RAM** (`run ~0xb101/0xb107`, found by `MaterializeSections
-Dc28x.mat.minSites=1` since it's a single section) **and** a larger **helper code section into LS
RAM** (`run ~0x8000-0x8fff`) that is invoked through **D0-RAM function pointers**
(`DAT_b040/b042/b044/b054`) set up at C-startup. That LS copy is neither memcpy-const nor a copy
table, so it is **not auto-materialized**; flash code calling those LS addresses leaves
"flow into uninitialized memory" marks. The flash-resident code + the D0 flash-write ramfunc are fully
analyzed; the LS section is a known gap (pinning its load/run/size needs tracing the `_c_int00`
pointer-dispatch). `_c_int00` is annotated with this note in each program.

## Step 5 — FinalizeRamfuncs (run AFTER analysis settles)

Two artifacts of Ghidra's auto-analysis, both needing background analysis to have run first (which a
script on the Swing/EDT thread cannot force):

1. **Stubbed bodies** — MaterializeSections binds each ramfunc before analysis has decoded every
   fall-through, so ~half get a 1-word body while their instructions sit loose. Pass 1 delete+recreates
   each default-named stub once decoded, binding the full body (dir_26_65_2: 65/65 full,
   `fixedPointDivide` = 0x47 words). **This holds.**

1b. **Stale flow-error bookmarks — cleared.** The import-time auto-analysis runs the disassembler
   **before** MaterializeSections fills the RAM, so it drops a *"Disassembly not permitted within
   uninitialized memory block"* (or *"…flow into non-existing memory"*) error bookmark at every flash
   `LCR`/branch into a RAM-resident function. Once the RAM is materialized those marks are **stale** —
   the target now holds real bytes. Pass 1b removes each whose flow target is now initialized/mapped,
   while **keeping** genuine gaps (target still uninitialized) and missing-opcode marks (*"Unable to
   resolve constructor"* — e.g. the SAT64/`0x56xx` SLEIGH backlog) so real issues stay visible.
   (dir_26_65_2: 308 stale cleared, 0 genuine; pmr: 95 cleared, 1 genuine kept.)

2. **False no-return truncation — SOLVED at the source (pspec).** Two heuristic analyzers,
   **"Non-Returning Functions - Discovered"** and **"Shared Return Calls"**, used to falsely mark the
   RAM ramfuncs non-returning and stamp a `CALL_RETURN` override on every flash `LCR` to them, deleting
   the flash fall-through into `??` data (e.g. `0xa82d2`, `0xa6511`). Mechanism (confirmed against
   Ghidra's `FindNoReturnFunctionsAnalyzer` source): the discovered analyzer runs early
   (`DISASSEMBLY.after().after()`), sees the not-yet-laid-down flash fall-through after ≥3 `LCR`s to
   the same freshly-materialized ramfunc as *"data after call"*, marks it non-returning, and
   `ClearFlowAndRepairCmd` deletes the fall-through — **self-reinforcing** (now it really *is* data
   after the call). It is an analyzer artifact, **NOT a SLEIGH bug** — `LCR`/`LRETR` emit correct
   `call` / `return [ret]` p-code.

   **The module now disables both analyzers by default** via language properties in `tms320c28x.pspec`
   (`enableNoReturnAnalysis=false`, `enableSharedReturnAnalysis=false`) — the exact opt-out both
   analyzers read in `getDefaultEnablement()` (ARM's own pspec disables shared-return the same way).
   This is deterministic and cannot oscillate, unlike a post-hoc script racing the analyzers. Verified
   on a fresh dir_26_65_2 import: 69 ramfuncs materialized, **0 marked non-returning, 0 `CALL_RETURN`
   overrides anywhere in flash** (was 94 peak / 35 residual before), and this pass-2 finds nothing to
   repair. Bare-metal DSP firmware has few genuine non-returning functions; if a specific image needs
   the detection, re-enable the two analyzers per-program in *Analysis Options*. Pass 2 remains as a
   belt-and-suspenders repair for exactly that case (a near no-op in the default configuration). It now
   covers **flash functions as well as RAM ramfuncs** — a stale no-return flag can ride in via a
   fresh-import+**merge** onto a flash function (the way precious hand-RE'd programs get updated), which
   the old RAM-only scope missed (e.g. `FUN_0008d934` on 12603 pmr: 1 flag + 29 truncated callers).

3. **Disassembly conflicts — repaired (looped with pass 2).** A multi-word instruction whose trailing
   operand word is *also* a valid standalone opcode (common in the FPU float code — `MOV32 mem32`
   operand words) gets truncated when an errant flow decodes that operand word first: *"Failed to
   disassemble at A due to conflicting instruction at B"*. Pass 3 clears `[A,B]` and re-disassembles
   `A` so it reclaims the operand word (restoring `B` on failure). Because pass 2's fall-through
   re-disassembly can itself spawn new conflicts, **passes 2 and 3 run in a loop until neither changes
   anything**, then stale flow bookmarks are re-cleared. (12603: `0x8a661`, `0x9e84f` reclaimed as
   `MOV32`.)

## Step 6 — RetypeWideMemory

Unchanged; run last to clean up the decompiler's 32/64-bit reads. See its script header.

## Step 7 — Residual-mark cleanup + verification (inline)

After the pipeline a handful of `Error`/`Bad Instruction` bookmarks usually remain. There is no
dedicated script yet — this is a short inline sweep. **Classify by the code unit under the mark:**

- **Mark on a NON-instruction (data/undefined) unit** → a phantom decode on a const pool, a load
  image, or padding. **Delete the bookmark.** (This is the bulk; a blanket tail-mark deletes them in
  one shot on tail-table images, but early-table / memcpy-const images leave them scattered.)
- **`Failed to resolve varnode <f_movf_reg>`** (loose, not in a function) → a committed-state
  misalignment artifact (a `MOV32` operand word decoded standalone; `f_movf_reg` values 0/2/3 are
  genuinely unused on the 8-reg FPU). A clean re-decode is fine — clear the loose unit and delete the
  mark.
- **Loose instruction that flows into uninitialized / non-existing memory** at a code↔data boundary
  (e.g. a function's last "instruction" runs into a float pool) → clear that one unit + delete the
  mark.
- **`halt_baddata` inside a materialized RUN region** → a float const-pool copied into LS/D RAM that
  got disassembled as code (e.g. an IEEE-754 pool at `run 0x9200`). Mark the run as data. (The current
  MaterializeCopyTable avoids this via ref-based run classification; MaterializeSections and any manual
  materialization can still hit it.)
- **Tiny phantom function in a ramfunc run region that branches to a bogus address** (`0x2xxxxx`,
  `0x3xxxxx` — outside the map) → embedded ramfunc data disassembled as code from a spurious ref.
  Delete the phantom function + clear its body.

**Calibrate — don't chase marks below a known-good baseline.** Run a coverage probe over the flash
range and compare against a *blessed* clean image of the same family: instruction %, defined-data %,
undefined %, and `Error`-mark count. A clean C28x DIR sits around **~84% insn / ~6% undef / ≤2 marks**
(e.g. `dir2026_clean` = 3140 fns, 83.8% insn, 5.9% undef, 2 marks). If a fresh image already matches
that envelope, the residual marks are cosmetic — stop. If undef% is much higher, a section is still
un-materialized (go back to Step 4/4b — or the dead-code check).

**Verify the point of it all:** count flash `LCR`/`SB` call sites into each ramfunc *run* region that
now bind to a real function (`getReferenceDestinationIterator` over the run range → callers ≥ `0x80800`).
Non-zero and matching the copy record's expected fan-in = the ramfunc is live and its callers resolve.

## Per-CPU / bootloader notes

- **CPU banks are separate, not aliased.** F28377D has a distinct 512KB flash bank *per CPU*, both at
  logical `0x80000-0xBFFFF` (SPRS880P Table 7-2). So `0x82000` on a CPU1 image (PMR / bootloader) and
  `0x82000` on a CPU2 image (DIR) are different physical sectors — set the base + run the CPU-correct
  `SetupF28377D` arg and analyze them as separate programs.
- **Sector map** (both banks): S0 `0x80000`, S1 `0x82000`, S2 `0x84000`, S3 `0x86000` (8KW each),
  S4 `0x88000` (32KW), S5 `0x90000`, … A resident PM bootloader occupies **S1–S3** (`0x82000-0x87FFF`);
  the CPU1 app starts at S4 (`0x88000`).
