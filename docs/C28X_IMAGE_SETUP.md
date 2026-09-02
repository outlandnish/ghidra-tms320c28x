# Setting up a headerless C28x firmware image for analysis

Turn a raw C28x flash dump into a fully analyzable Ghidra program — from import
through recovering the RAM-resident code the app copies out of flash at startup.
Every step is a script in the **TMS320C28x** Script-Manager category.

## Pipeline

| # | Step | What it does |
|---|------|--------------|
| 0 | **Import + set base** | Load the raw `.bin` as `TMS320C28x:LE:32:default` (F28377D) or `…:f2812`. Set the image base to the flash word address the dump starts at. See the byte-swap note. |
| 1 | `SetupF28377D.java` (or `SetupF2812.java`) | Map the device memory — peripheral MMIO frames **and the on-chip RAM regions**, split into their datasheet banks (`M0`/`M1`, `LS0`…`LS5`, `D0`/`D1`, `GS0-15`, CLA/CPU MSGRAMs) with correct perms (SARAM → **RWX** since ramfuncs run there; ROM → RX; message RAM → RW). Also maps the DCAN `CANA`/`CANB` message RAM (`0x49000`/`0x4b000`) and (CPU1) the uPP message RAM. Mapping RAM is what lets calls into it resolve later. Pass `CPU1` or `CPU2` as the script arg — CPU1 has device-unique peripherals (UPP/XBAR/USBA/DEV_CFG) that only get labeled when the arg matches. |
| 2 | `SeedFunctions.java` | Recover functions from the bytes (call targets + prologues) and add call-site→target refs. Call targets pass a **boundary gate** so a coincidental word pair inside a numeric table cannot invent a target in the middle of a real instruction. Also recovers `_c_int00` and marks it an entry point — see below. |
| 3 | `MarkJumpTables.java`, `MarkDataTables.java` | Mark switch/pointer tables and float-constant pools as data so they stop decoding as garbage. |
| 4 | `MaterializeSections.java` or `MaterializeCopyTable.java` | Copy the flash **load images** into their RAM **run** addresses so the RAM-resident code/data becomes real. Which one depends on the startup copy mechanism. |
| 4c | `EmulateStartup.java` | The general alternative to 4/4b: **run the image's own `_c_int00`** and keep the RAM it writes. Covers whatever mechanism the image uses — including the inlined `.cinit` walk that neither materializer implements. Dry run by default. |
| 4d | `MarkComponentRegistry.java` | Turns the materialized RAM dispatch table into actual call-graph **references**. 4/4b/4c restore the bytes; without this the graph never sees the indirect edges and every handler still looks dead. Finds the table structurally, reads each dispatcher's descriptor field offset out of the code, creates functions at proven call targets, and recovers a dispatcher's own function when nothing calls it either. Idempotent; `-Dc28x.reg.dryRun` to preview. |
| 5 | `FinalizeRamfuncs.java` | Post-analysis cleanup: rebuild bodies, clear stale flow bookmarks, repair conflicts. Run it **after** analysis has settled. |
| 8 | `ReachabilityReport.java` | What is actually reachable from `_c_int00`, and *why* the rest is not. Run last — it is only as good as the reference graph. |
| 6 | `RetypeWideMemory.java` | Retype 32/64-bit memory operands to kill `CONCAT22`/`CONCAT44` in the decompiler. |
| 7 | `SweepResidualMarks.java` + verify | Classify leftover `Bad Instruction` marks, delete only the provably cosmetic ones, and confirm against a known-good baseline. |

### The byte-swap

Some C28x flash images ship byte-swapped (byte pairs reversed relative to the
on-chip word layout). If yours is one of them, produce a swapped `.bin` first,
import THAT, and set the base. In this `wordsize=2` space Ghidra's
`Address.getOffset()` returns a **byte** offset (= word × 2) while TI's
`dis2000` prints **word** addresses — divide by 2 when comparing. Scripts that
walk the listing already account for this.

## Step 2b — the C-runtime entry (`_c_int00`)

Per **SPRU513Z** (*TMS320C28x Assembly Language Tools*) §3.3.1, `_c_int00` is the
C/C++ startup (boot) routine, and the name means it is **the interrupt handler
for interrupt number 0, RESET**; §3.3.2.3 notes the linker defines `_c_int00` as
the program entry point. §3.2 adds that the device cannot read the entry-point
field out of the object file, so it is encoded in the program in one of three
ways: a **bootloader's boot table** branches to it, it is installed as the
**RESET interrupt handler**, or a **hosted debugger** sets PC to it.

The startup routine's responsibilities, in order:

1. set up status and configuration registers
2. set up the stack
3. process the `.cinit` table to autoinitialize globals (`--rom_model`)
4. call all global object constructors in `.init_array` (EABI) / `.pinit` (COFF)
5. call `main`
6. call `exit` when `main` returns

A partial flash dump usually omits the sector holding the reset vector / boot
table, so Ghidra never learns where execution starts. `_c_int00` is then
invisible to every other seed signal: nothing *calls* it under any of the three
encodings above, and it opens with status-register setup rather than the
callee-saved pushes signal B looks for. The image has **no flow anchor at all** —
the startup path is never disassembled, so the `.cinit`/copy-table call chain and
anything reached only from it stay dark, and you cannot emulate from reset.

`SeedFunctions` recovers it in three steps; the first two key directly off
responsibilities 2 and 1:

1. **Anchor** on the word `0x28AD` = `MOV @SP,#16bit` (responsibility 2).
   Absolute stack-pointer initialization is the one thing only a C-runtime entry
   does — compiled C moves SP with `ADDB`/`SUBB SP,#imm`, never a literal load.
   It occurs *once* per application image in the corpus tested.
2. **Corroborate** within `crtWindow` words (responsibility 1): at least
   `crtMinModeOps` **distinct** members of the C28x configuration-register trio —
   `SETC OBJMODE` (`0x561F`), `CLRC AMODE` (`0x5616`), `SETC M0M1MAP` (`0x561A`) —
   plus at least one `LCR`, since responsibilities 3-6 are reached by call
   (`__TI_auto_init`, then `main`).

That the spec orders **configuration registers before the stack** is exactly why
step 3 below is needed: the true entry sits a few words *before* the anchor, at
the start of the status-register setup rather than at the SP load.
3. **Walk back** to the true first instruction. The anchor sits *inside*
   `_c_int00` — the application entries in the corpus open
   `SETC INTM|DBGM ; MOV @AL,#0 ; MOV IER,@AL` three words earlier, while the
   bootloader entries start at the anchor. Seeding the anchor would repeat the
   off-by-one that section B of the script warns about, and would additionally
   point the program's entry point at the middle of a function. So the script
   reuses the boundary gate's **backward linear-sweep resynchronization**:
   decode forward from each of the preceding `crtBackoff` words, keep only the
   streams that land exactly on the anchor, and in each take the last flow
   terminator (`LRETR`/`LRET`/`IRET`, or any no-fall-through op) before it — the
   entry is the instruction after it, since functions are emitted back-to-back.
   Streams vote; a stream that desyncs abstains.

The recovered entry is created as a function, named, given a plate comment, and
**registered as an external entry point** — that last part is what re-roots
analysis and emulation.

Measured over 5 F28377D images / 658k words — four application images spanning
three firmware generations, plus a bootloader: **8 anchors → 7 entries
recovered, 1 rejected** by the corroboration gate (a `0x28AD` scoring 0/3 mode
ops with no `LCR`). Every accepted entry drew a **unanimous** vote across 20–24
back-offs, and the one case with independent ground truth resolved to exactly
the hand-recovered address.

**Multiple entries are normal, not an error.** The bootloader image yields
three — that flash region links several C-runtime units. When there is more than
one, none is promoted to the bare `_c_int00` name; each is named
`_c_int00_<wordaddr>` so nothing implies a choice the bytes don't support.

Properties: `-Dc28x.seed.noCrtScan` (disable), `-Dc28x.seed.crtWindow`,
`-Dc28x.seed.crtMinModeOps`, `-Dc28x.seed.crtBackoff`. A name you chose is never
overwritten, and an entry already owned by another function is reported and left
alone.

## Step 4 — MaterializeSections

**Why.** On TI-RTS C28x images, time-critical code (`.ramfunc` — flash
program/erase, motor-control inner loops) and initialized data (`.cinit`) live
in **flash at a LOAD address** and are copied to **RAM at a RUN address** by the
application's own C-runtime startup (not the bootloader). In a static flash-only
dump the RAM run regions are uninitialized, so an `LCR 0x9669`-into-RAM hits
"Disassembly not permitted within uninitialized memory block" and every
RAM-resident function is invisible with its (often 100+) flash callers dangling.
The flash dump already contains everything needed — you just have to replay the
copy.

**How it finds the copies.** A startup dispatcher calls a tight word-memcpy
(`memcpyWords(count, dst, src)`) once per section with constant
`(size, RAM-run, flash-load)` args. The script forward-const-propagates, snapshots
the live constants at each call, and forms `(size, run, load)` triples where
`load` is in the flash image, `run` is mapped RAM above the M0/M1 scratch
(`≥ 0x800`), and `size` is a non-pointer count. It groups triples by **callee**
(robust: the call reference is always present, unlike function binding, which
analysis applies non-deterministically) and picks the copy routine by
**disjoint-section count + presence of a CODE section** — real sections have
non-overlapping runs and only the ramfunc-copier moves code, so a scratch-buffer
helper (many copies to one run) loses.

**Per section:** convert the overlapped RAM block(s) to initialized and
`setBytes` the flash load-image in, **splitting the write at the LS0-5 / D0-1
seam at word `0xB000`**. A CODE section (run region has incoming CALL refs from
flash) is marked executable, then each CALL-target is disassembled (all first,
then bound — a single interleaved pass stubs ~half the functions) and turned
into a function. The section's flash LOAD image is marked as `undefined2[]` and
its phantom duplicate functions dropped — the load image is byte-identical to
the RAM run image but is never executed in place.

Properties: `-Dc28x.mat.dryRun`, `-Dc28x.mat.copyfn=0xWORD` (force the copy
routine), `-Dc28x.mat.minSites`, `-Dc28x.mat.disasm`. Additive and idempotent;
never overwrites a user symbol.

## Step 4b — MaterializeCopyTable (compressed `__TI_auto_init` copy-table images)

Newer C28x builds copy `.ramfunc`/`.cinit` via a **compressed copy table**
instead of memcpy-with-constant-args. The tell: MaterializeSections prints
**"NO copy routine found"** yet the image still has hundreds of flash `LCR`s
into uninitialized RAM. Use `MaterializeCopyTable.java`.

The table (auto-detected structurally, or forced with `-Dc28x.ct.base=0xWORD`)
is a run of 6-word records `{size:u32, load:u32, run:u32}` terminated by an
all-`0xffffffff` record:

- `size != 0` → **raw copy**: `size` words from flash `load` to RAM `run`.
- `size == 0` → **handler dispatch**: `*load` is a handler index; payload starts
  at `load+1`. The script implements the TI **LZSS** handler: read a 16-bit
  control word (LSB first); for each bit, `1` = copy one literal word from src,
  `0` = back-reference word `W` with `len=(W&0xf)+2` (if `len==0x11`,
  `len = nextWord + 0x11`) and `off=(W>>4)&0xfff` (if `off==0xfff`, END) — copy
  `len` words from `dest-1-off`.

Each section is written to RAM (splitting across the LS/D seam), then each run
region is **classified by incoming CALL/JUMP references, not by address**: a run
is code iff at least one address in it has a call/jump ref (from a flash `LCR`
or another ramfunc). Code runs are disassembled at every call/jump target and
bound to functions; **data runs — float const pools or `.cinit` copied into
LS/D RAM with zero code refs — are marked `undefined2[]`**. A naive
address-range rule (`0x8000 ≤ run < 0xc000 ⇒ code`) would disassemble an
IEEE-754 pool copied to e.g. `run 0x9200` and produce `halt_baddata`;
ref-classification avoids that and also picks up **M0-RAM** code runs
(`run < 0x8000`, e.g. an ISR block at `0x122`) that a range rule skips.

**Flash-tail marking is position-aware.** The copy table + const pools + load
images are marked as `undefined2[]` so they stop decoding as phantom functions.
When the table sits near flash-**end** (load images clustered after it), a
single blanket `[table … flash-end]` mark is used. When the table sits
**early**, the bulk of executable flash lies **between** the table and the tail
load images, so a blanket mark would erase code — the script detects this
(table not in the last ⅛ of flash) and instead marks only the table extent +
each record's load-image extent. `-Dc28x.ct.noTailData=true` disables all
marking. Run FinalizeRamfuncs afterwards. Detection is conservative (terminator
+ valid handler index), so on a memcpy-const image it finds nothing and you
fall back to MaterializeSections.

Two on-disk copy-table **variants** exist; both surface as MaterializeSections
printing "NO copy routine found":

- **LZSS `{size,load,run}`, 6-word records** — the form above, handled directly.
- **RAW `{load,run,size,flags}`, 8-word records**, all raw copies (no LZSS
  handler, so `MaterializeCopyTable`'s handler-requiring detector skips it).
  Materialize inline by walking the 8-word records (terminated by
  `0xffffffff`) and copying `size` words `load→run`, then applying the same
  ref-based run classification. (Generalizing the detector to this variant is a
  TODO.)

### When neither materializer auto-detects the copy

If both print "not found" but the image still has flash `LCR`s into
uninitialized RAM, work down this list:

1. **Single-section image.** The copier is often a general `memcpyWords` called
   once with constant `(size, run, load)` — MaterializeSections needs ≥2
   disjoint sections by default. Re-run with **`-Dc28x.mat.minSites=1`** (and
   `-Dc28x.mat.copyfn=0xWORD` if the routine is ambiguous). Small
   resident-loader images that copy a single flash-write ramfunc to D0 RAM fit
   this pattern.
2. **RAW 8-word copy table** (above): locate it by scanning flash for a known
   RAM *run* address as a 32-bit value; the surrounding words are the
   `{load,run,size}` triple. Materialize inline (copy `size` words `load→run`)
   then apply ref-based run classification.
3. **It may be DEAD CODE, not a live section.** Before assuming a
   materialization gap, prove the run region is actually used:
   (a) does anything **write/copy** into it? (any write/data ref into the run
   range) (b) is the flash code that references it **reachable from
   `_c_int00`** (call-graph BFS — check indirect reach too: stored
   function-pointers, jump-table entries). If it is **unreferenced AND never
   written**, it is orphaned/dead flash, not a section to materialize. Don't
   chase it.

### Resident-loader / boot-updater images — LS-RAM section NOT auto-materialized

Some small resident-loader images copy a flash-write ramfunc to D0 RAM (found
by `MaterializeSections -Dc28x.mat.minSites=1` since it's a single section)
**and** a larger helper code section into LS RAM that is invoked through
D0-RAM function pointers set up at C-startup. That LS copy is neither
memcpy-const nor a copy table, so it is **not auto-materialized**; flash code
calling those LS addresses leaves "flow into uninitialized memory" marks. The
flash-resident code + the D0 flash-write ramfunc are fully analyzed; the LS
section is a known gap (pinning its load/run/size needs tracing the
`_c_int00` pointer-dispatch).

## Step 4c — EmulateStartup (replay startup instead of reimplementing it)

`MaterializeSections` and `MaterializeCopyTable` each re-implement one startup
mechanism in Java — memcpy-with-constants, and the TI copy table with a
hand-written LZSS decoder. That only ever covers mechanisms someone has already
reversed. A third form is common and implemented by **neither**: the `.cinit`
record walk TI emits *inline into `_c_int00`* (`__TI_CINIT_Base`, which
`SeedFunctions` labels). The firmware already contains a correct implementation
of all of them, so `EmulateStartup` runs it.

Execution starts at `_c_int00` and stops at the application handoff
(`_args_main`/`main`/`exit` — found by symbol, else derived from `_c_int00`'s
shape, so it works on programs analysed before signal D existed). Two things are
deliberately not executed: `__TI_auto_init` (despite the name, the
global-constructor runner — arbitrary application code) and indirect calls (the
`.pinit` constructor loop). Ghidra's own write tracking records every store;
only writes landing in RAM blocks are kept, so peripheral pokes are counted and
discarded and flash is never touched. **Dry run by default — pass the script
argument `apply` to write.**

Verified on an F28377D application image: stops cleanly at the handoff after
~128k steps, writes 20,326 words into GS RAM, and reproduces all three `.cinit`
records that were decoded by hand from the table — destination and 32-bit value
both — exactly. The component-dispatch registry comes back populated with real
flash function pointers instead of zeros, which is the whole point: those
pointers are what turn indirect dispatch into references Ghidra can follow.

**This is also the sharpest ISA test in the tree.** Replaying real startup found
two SLEIGH semantic holes that decode parity is structurally blind to, because
the mnemonic and operands are correct either way — `ADDB ACC,#8bit` setting no
flags, and `PREAD` setting no N/Z. It also surfaced the `*XAR7` repeat shadow
(SPRU430F: a repeated `PREAD` advances an *internal* copy of the address, so the
source walks forward while the architectural `XAR7` stays put), now modelled in
the state modifier. See `EmuAddbAccFlagsTest`, `EmuPreadFlagsTest`,
`EmuPreadRepeatTest`.

## Step 5 — FinalizeRamfuncs (run AFTER analysis settles)

Three artifacts of Ghidra's auto-analysis, all needing background analysis to
have run first (which a script on the Swing/EDT thread cannot force):

1. **Stubbed bodies.** MaterializeSections binds each ramfunc before analysis
   has decoded every fall-through, so ~half get a 1-word body while their
   instructions sit loose. Pass 1 deletes+recreates each default-named stub
   once decoded, binding the full body.

1b. **Stale flow-error bookmarks — cleared.** Import-time auto-analysis runs
   the disassembler **before** MaterializeSections fills the RAM, so it drops a
   *"Disassembly not permitted within uninitialized memory block"* (or
   *"…flow into non-existing memory"*) error bookmark at every flash
   `LCR`/branch into a RAM-resident function. Once the RAM is materialized
   those marks are **stale** — the target now holds real bytes. Pass 1b removes
   each whose flow target is now initialized/mapped, while **keeping** genuine
   gaps (target still uninitialized) and missing-opcode marks (*"Unable to
   resolve constructor"*) so real issues stay visible.

2. **False no-return truncation — prevented at the source (pspec).** The
   heuristic **"Non-Returning Functions - Discovered"** and **"Shared Return
   Calls"** analyzers, running early (`DISASSEMBLY.after().after()`), can see a
   flash fall-through after ≥3 `LCR`s to the same freshly-materialized ramfunc
   as *"data after call"*, mark the ramfunc non-returning, and let
   `ClearFlowAndRepairCmd` delete the fall-through — **self-reinforcing** (now
   it really *is* data after the call). It's an analyzer artifact, not a SLEIGH
   bug — `LCR`/`LRETR` emit correct `call` / `return [ret]` p-code.

   `tms320c28x.pspec` disables both analyzers by default
   (`enableNoReturnAnalysis=false`, `enableSharedReturnAnalysis=false`) — the
   exact opt-out both analyzers read in `getDefaultEnablement()`. Deterministic
   and cannot oscillate. If a specific image needs the detection (bare-metal DSP
   firmware has few genuine non-returning functions), re-enable them
   per-program in *Analysis Options*. Pass 2 is a belt-and-suspenders repair
   that covers this case plus stale no-return flags that ride in via a
   fresh-import+**merge** onto a flash function.

3. **Disassembly conflicts — repaired (looped with pass 2).** A multi-word
   instruction whose trailing operand word is *also* a valid standalone opcode
   (common in the FPU float code — `MOV32 mem32` operand words) gets truncated
   when an errant flow decodes that operand word first: *"Failed to disassemble
   at A due to conflicting instruction at B"*. Pass 3 clears `[A,B]` and
   re-disassembles `A` so it reclaims the operand word (restoring `B` on
   failure). Because pass 2's fall-through re-disassembly can spawn new
   conflicts, **passes 2 and 3 loop until neither changes anything**, then
   stale flow bookmarks are re-cleared.

## Step 6 — RetypeWideMemory

Unchanged; run last to clean up the decompiler's 32/64-bit reads. See its
script header.

## Step 7 — Residual-mark cleanup + verification

After the pipeline a handful of `Error`/`Bad Instruction` bookmarks usually
remain. `SweepResidualMarks.java` performs the classification below and deletes only the
cosmetic class. It is a **dry run by default** — pass `apply` to actually delete. Anything
it cannot prove cosmetic it keeps and prints, so real gaps stay visible.

Two rules matter more than they look:

- A mark **inside a function body** is never cosmetic, even when the code unit under it is
  *undefined* rather than an instruction. That pairing is the signature of a missing
  opcode: `SeedFunctions` bound a function whose first word would not decode. It used to be
  equally often a false seed landing on an **operand word** — `SeedFunctions`' boundary gate
  now refuses those at the source, but an image seeded by an older build (or with
  `-Dc28x.seed.noBoundaryGate`) still carries them, and they are indistinguishable from an
  ISA gap by inspection. Either way, check `run_fw_parity` against TI before concluding a
  mark is a real ISA gap. (Observed on an F28377D application image: a seed at the second
  word of a 2-word `MOV T,#imm16` produced a 1-word stub function and an
  unresolvable-constructor mark; the genuine ISA gap in that same range was a different
  address entirely.)
- `Disassembly not permitted within uninitialized memory block` names no target address,
  so it needs its own case; it means an un-materialized section — back to step 4/4b.

**Classify by the code unit under the mark:**

- **Mark on a NON-instruction (data/undefined) unit** → a phantom decode on a
  const pool, a load image, or padding. **Delete the bookmark.** (This is the
  bulk; a blanket tail-mark deletes them in one shot on tail-table images, but
  early-table / memcpy-const images leave them scattered.)
- **`Failed to resolve varnode <f_movf_reg>`** (loose, not in a function) → a
  committed-state misalignment artifact (a `MOV32` operand word decoded
  standalone; `f_movf_reg` values 0/2/3 are genuinely unused on the 8-reg FPU).
  A clean re-decode is fine — clear the loose unit and delete the mark.
- **Loose instruction that flows into uninitialized / non-existing memory** at
  a code↔data boundary (e.g. a function's last "instruction" runs into a float
  pool) → clear that one unit + delete the mark.
- **`halt_baddata` inside a materialized RUN region** → a float const-pool
  copied into LS/D RAM that got disassembled as code (e.g. an IEEE-754 pool at
  `run 0x9200`). Mark the run as data. (MaterializeCopyTable's ref-based
  classification avoids this; MaterializeSections and manual materialization
  can still hit it.)
- **Tiny phantom function in a ramfunc run region that branches to a bogus
  address** (`0x2xxxxx`, `0x3xxxxx` — outside the map) → embedded ramfunc data
  disassembled as code from a spurious ref. Delete the phantom function +
  clear its body.

**Calibrate — don't chase marks below a known-good baseline.** Compare against
a blessed clean image of the same family: instruction %, defined-data %,
undefined %, `Error`-mark count. A clean C28x application image typically sits
around **~84% insn / ~6% undef / ≤2 marks**. If a fresh image matches that
envelope, residual marks are cosmetic — stop. If undef% is much higher, a
section is un-materialized (back to Step 4/4b — or the dead-code check).

**Verify the point of it all:** count flash `LCR`/`SB` call sites into each
ramfunc *run* region that now bind to a real function
(`getReferenceDestinationIterator` over the run range → callers ≥ `0x80800`).
Non-zero and matching the copy record's expected fan-in = the ramfunc is live
and its callers resolve.

## Step 8 — ReachabilityReport (what is live, and why the rest is not)

With `_c_int00` recovered there is finally a root, so the call graph can be
walked. The report splits the unreachable set by *why* nothing reaches it:
**DATA REFS ONLY** (address stored somewhere but never called from live code —
fn-ptr tables, ISR vectors; usually live, and the highest-value bucket),
**called only by unreachable code** (orphaned components — follow them to a root
in the first bucket), and **NO REFS AT ALL**.

**Read a low percentage as a missing-edge result, not a dead-code result.** On a
component/task-dispatch firmware the dispatcher calls through a function-pointer
registry that `.cinit` fills in at runtime, so until startup is replayed those
pointers are inert flash words and live handlers look unreferenced. Measured on
an F28377D application image straight out of the pipeline: **53 of 2139
functions reachable (2.5%)**, with a 1371-word function that had been confirmed
live by hand sitting in NO-REFS-AT-ALL. Nothing was dead — the registry had
simply never been filled in.
The script warns when the fraction is implausibly low and points at Step 4c.

**Materializing is necessary but NOT sufficient — Step 4c alone does not move
this number.** Verified on a clean import of that image: after `EmulateStartup
apply` wrote the registry into RAM, reachability was still **53 / 2140 (2.5%)**.
Materialization restores the *bytes*; the graph is built from *references*, and
nothing in Step 4c turns a materialized RAM pointer word into an edge. That is
what **Step 4d (`MarkComponentRegistry`)** is for.

Running Step 4d on that image takes it to **112 / 2174 (5.2%)**, with
NO-REFS-AT-ALL falling 493 → 405. That is a much smaller jump than the edge count
suggests, and the reason is worth internalizing: **the remaining gap is a rooting
problem, not an edge problem.** The component dispatchers are themselves called
from flash *task-table records* (`{fn, 0, state, state, rate, period, …}`, not a
dense pointer run, so `MarkJumpTables` does not see them either) — and nothing in
the image references those records. So the scheduler and all three dispatchers
have **zero** incoming references and stay unrooted, stranding everything below
them in "called only by unreachable code", which is why that bucket *grows*.

Measure the latent value by rooting them by hand — pass the scheduler and the
dispatchers (Step 4d prints their addresses) as extra roots:

```
ReachabilityReport -Dc28x.reach.roots=<scheduler>,<dispatcher>,...
  -> 1096 / 2174 reachable (50.4%)
```

So the edges Step 4d creates are real and worth ~980 functions; they are gated
behind one more indirection layer (whatever registers those task-table records
with the OS tick). Chase that layer next — it is the single highest-value
remaining edge in the pipeline. Until then, read a low percentage as **"not yet
rooted"**, and use `-Dc28x.reach.roots` to see past it.

## Per-CPU notes (F28377D)

- **CPU banks are separate, not aliased.** F28377D has a distinct 512KB flash
  bank *per CPU*, both at logical `0x80000-0xBFFFF` (SPRS880P Table 7-2). So
  `0x82000` on a CPU1 image and `0x82000` on a CPU2 image are different
  physical sectors — set the base + run the CPU-correct `SetupF28377D` arg and
  analyze them as separate programs.
- **Sector map** (both banks): S0 `0x80000`, S1 `0x82000`, S2 `0x84000`,
  S3 `0x86000` (8KW each), S4 `0x88000` (32KW), S5 `0x90000`, … A resident
  loader typically occupies **S1–S3** (`0x82000-0x87FFF`); the CPU1 application
  starts at S4 (`0x88000`).
