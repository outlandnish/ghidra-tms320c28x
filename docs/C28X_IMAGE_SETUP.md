# Setting up a headerless C28x firmware image for analysis

The full recipe to turn a raw, byte-swapped C28x flash dump into a fully analyzable Ghidra
program — from import through recovering the RAM-resident code that the app copies out of flash
at startup. Every step is a script in the **TMS320C28x** Script-Manager category.

## Pipeline

| # | Step | What it does |
|---|------|--------------|
| 0 | **Import + set base** | Load the raw `.bin` as `TMS320C28x:LE:32:default` (F28377D) or `…:f2812`. Set the image base to the flash word address (e.g. `0x82000` for a DIR, `0x88000` for a PMR). See below on the byte-swap. |
| 1 | `SetupF28377D.java` (or `SetupF2812.java`) | Map the device memory — peripheral MMIO frames **and the on-chip RAM regions**, split into their datasheet banks (`M0`/`M1`, `LS0`…`LS5`, `D0`/`D1`, `GS0-15`, CLA/CPU MSGRAMs) with correct perms (SARAM → **RWX** since ramfuncs run there; ROM → RX; message RAM → RW). Also maps the DCAN `CANA`/`CANB` message RAM (`0x49000`/`0x4b000`) and (CPU1) the uPP message RAM. Mapping RAM is what lets calls into it resolve later. |
| 2 | `SeedFunctions.java` | Recover functions from the bytes (call targets + prologues) and add call-site→target refs. |
| 3 | `MarkJumpTables.java`, `MarkDataTables.java` | Mark switch/pointer tables and float-constant pools as data so they stop decoding as garbage. |
| 4 | **`MaterializeSections.java`** | Copy the flash **load images** into their RAM **run** addresses so the RAM-resident code/data becomes real. See below. |
| 5 | **`FinalizeRamfuncs.java`** | Post-analysis cleanup of the materialized ramfuncs (rebuild bodies; repair flash callers). Run it **after** analysis has settled. See below. |
| 6 | `RetypeWideMemory.java` | Retype 32/64-bit memory operands to kill `CONCAT22`/`CONCAT44` in the decompiler. |

### The byte-swap

Tesla PM/DI flash images are **byte-swapped**. Produce a swapped `.bin` first (`c28x_loadimg.py
--mode swap` in the tm3diag repo), import THAT, and set the base. In this `wordsize=2` space
Ghidra's `Address.getOffset()` returns a **byte** offset (= word × 2) while TI's `dis2000` prints
**word** addresses — divide by 2 when comparing. Scripts that walk the listing already account for
this.

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
