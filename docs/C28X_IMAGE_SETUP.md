# Setting up a headerless C28x firmware image for analysis

The full recipe to turn a raw, byte-swapped C28x flash dump into a fully analyzable Ghidra
program — from import through recovering the RAM-resident code that the app copies out of flash
at startup. Every step is a script in the **TMS320C28x** Script-Manager category.

## Pipeline

| # | Step | What it does |
|---|------|--------------|
| 0 | **Import + set base** | Load the raw `.bin` as `TMS320C28x:LE:32:default` (F28377D) or `…:f2812`. Set the image base to the flash word address (e.g. `0x82000` for a DIR, `0x88000` for a PMR). See below on the byte-swap. |
| 1 | `SetupF28377D.java` (or `SetupF2812.java`) | Map the device memory — peripheral MMIO frames **and the on-chip RAM regions** (M0/M1, LS0-5, D0/D1, GS0-15, MSGRAMs). Mapping RAM is what lets calls into it resolve later. |
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

2. **False no-return truncation** — two heuristic analyzers, **"Non-Returning Functions - Discovered"**
   and **"Shared Return Calls"**, falsely mark the RAM ramfuncs non-returning and stamp a `CALL_RETURN`
   override on every flash `LCR` to them, deleting the flash fall-through into `??` data (e.g.
   `0xa82d2`, `0xa6511`). **This is an analyzer artifact, NOT a SLEIGH bug** — `LCR`/`LRETR` emit
   correct `call` / `return [ret]` p-code. Pass 2 disables both analyzers and clears the flag +
   overrides, but **the repair does not reliably hold from a script**: pass-1's rebuilds re-trigger
   analysis that re-applies the overrides, and they oscillate. Re-running the script converges them
   down but not cleanly to zero.

   **Durable fix (planned): a module `AbstractAnalyzer`.** Running inside the analysis pipeline (off
   the Swing thread, at a late priority) it can undo the two heuristics' damage deterministically each
   session instead of racing them post-hoc. Until it exists, treat the truncated flash callers as a
   known cosmetic artifact, or disable those two analyzers in *Analysis Options* before importing.

## Step 6 — RetypeWideMemory

Unchanged; run last to clean up the decompiler's 32/64-bit reads. See its script header.
