# ghidra-tms320c28x

A Ghidra processor module (SLEIGH) for the Texas Instruments **TMS320C28x** DSP core.
Two device targets share one SLEIGH core (the C28x instruction set is common; the
`.sla` is identical):

- **TMS320F28377D** — dual-core C28x + FPU + VCU (F2837xD family). Language
  `TMS320C28x:LE:32:default`; peripherals via `SetupF28377D.java`.
- **TMS320F2812** — the original fixed-point C28x (F281x family; no FPU/VCU/TMU/CLA),
  also covering the memory-compatible F2810/F2811. Language `TMS320C28x:LE:32:f2812`;
  peripherals via `SetupF2812.java`. See [docs/c28x/f2812_memmap.md](docs/c28x/f2812_memmap.md).

> **WIP / vibe-coded.** This module was substantially generated with the help of
> Claude Code (an LLM coding agent) working against the TI reference manuals — every
> constructor, script, and doc has a human in the loop but the initial drafts are
> LLM-authored. Verify against the SPRU430F / SPRUHS1C reference before trusting any
> decode for critical work, and please file issues. See [THIRD-PARTY.md](THIRD-PARTY.md)
> for provenance of TI-derived material.
>
> **Not affiliated with Texas Instruments** or the National Security Agency.
> "TMS320" / "C2000" are TI trademarks used here only to identify the target hardware.

## Setup — add this processor to your Ghidra

**Requirements:** Ghidra **12.x** (built against 12.1.2). The compiled `.sla` is a build
artifact and is not checked into the repo — grab it from a release, from CI artifacts, or
compile it yourself (see below).

### Install (pick one)

**Option A — packaged extension (recommended).** Download the latest `ghidra-tms320c28x-*.zip`
from the [GitHub Releases](https://github.com/outlandnish/ghidra-tms320c28x/releases) page
(published by CI on each release), then in Ghidra:
**File ▸ Install Extensions ▸ +**, pick the zip, and restart.

To build the zip yourself instead:

```sh
gradle -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR     # produces dist/*.zip
```

**Option B — drop-in install.** Copy the module into your Ghidra processors dir so it loads
at startup. This requires a compiled `data/languages/tms320c28x.sla` — either download it
from the release page (attached as `tms320c28x.sla`) or compile it locally:

```sh
"$GHIDRA_INSTALL_DIR/support/sleigh" data/languages/tms320c28x.slaspec
```

Then:

```sh
# Linux / macOS
cp -r ghidra-tms320c28x "$GHIDRA_INSTALL_DIR/Ghidra/Processors/TMS320C28x"
```
```powershell
# Windows (PowerShell)
Copy-Item -Recurse ghidra-tms320c28x "$env:GHIDRA_INSTALL_DIR\Ghidra\Processors\TMS320C28x"
```

The folder must contain `data/languages/tms320c28x.sla`. **Restart Ghidra** — it scans
`Processors/` only at startup.

### Verify it loaded

1. New project ▸ **File ▸ Import File** ▸ choose a raw C28x binary.
2. In the language picker, click the browse button and confirm **`TMS320C28x:LE:32:default`**
   is listed. Select it.
3. After import, **Window ▸ Register Manager**: `ACC` should show `AH`/`AL` sub-pieces.
4. Quick smoke test: in the listing, disassemble bytes `01 00` → `ABORTI`, `21 76` → `IDLE`.

### Loading a raw firmware image

This is a **word-addressable** architecture (1 address = 16 bits, not 8).

> **Tooling note:** in this `wordsize=2` space, Ghidra's `Address.getOffset()` returns a
> **byte** offset (= word × 2), while TI's `dis2000` prints **word** addresses. Divide by 2
> when comparing the two — this trips up every script that walks the listing.

### Analyzing a headerless raw image — the script pipeline

A raw firmware `.bin` has no symbols or entry points, so Ghidra's analyzer finds almost
nothing. The bundled scripts (Script Manager, category **TMS320C28x**) recover the code,
separate it from the embedded data tables, replay the startup's flash→RAM copies, and rebuild
the call graph. Run them **in this order** — the numbering matches
[docs/C28X_IMAGE_SETUP.md](docs/C28X_IMAGE_SETUP.md):

| # | Script | What it does |
|---|--------|--------------|
| 0 | *import + set base* | Load the raw `.bin` as `TMS320C28x:LE:32:default` (F28377D) or `…:f2812`; base = the flash **word** address the dump starts at. |
| 1 | `SetupF28377D` / `SetupF2812` | Map the device memory — peripheral frames **and the on-chip RAM banks**. Takes `CPU1`/`CPU2` on F28377D. |
| 2 | `SeedFunctions` | Functions from absolute **call targets** (LCR/LC/FFC) and **prologue patterns**, plus call-site→target refs. Also recovers `_c_int00` and registers it as an entry point — the only flow anchor a headerless dump has. |
| 3 | `MarkJumpTables`, `MarkDataTables` | Mark switch/case **pointer tables** and **float const pools** as data so they stop decoding as garbage. |
| 4 | `MaterializeSections` **or** `MaterializeCopyTable` | Copy the flash **load** images to their RAM **run** addresses, so `.ramfunc` code becomes real and its flash callers resolve. Which one depends on the startup copy mechanism — `NO copy routine found` from the first means try the second. |
| 4c | `EmulateStartup` | The general alternative to 4: **run the image's own `_c_int00`** and keep the RAM it writes. Covers mechanisms neither materializer implements (the `.cinit` walk TI emits inline). Dry run unless passed `apply`. |
| 4d | `MarkComponentRegistry` | Turn the materialized dispatch tables into call-graph **references**, and root the handlers behind them. |
| 5 | `FinalizeRamfuncs` | Run **after** auto-analysis settles: rebuild ramfunc bodies, clear stale flow bookmarks, repair disassembly conflicts. |
| 5b | `MergeSplitFunctions` | Reunite functions step 2 cut in two at a mid-function register push it mistook for a prologue. |
| 6 | `RetypeWideMemory` | Retype 32/64-bit memory operands to kill `CONCAT22`/`CONCAT44` in the decompiler. |
| 7 | `SweepResidualMarks` | Classify the leftover `Bad Instruction` / `Error` marks and delete only the provably cosmetic ones. Dry run unless passed `apply`. |
| 8 | `ReachabilityReport` | What is actually reachable from `_c_int00`, and *why* the rest is not. Run last — it is only as good as the reference graph. |

**Step 1 is not optional and it comes first.** Mapping the RAM is what lets calls into it
resolve at all; without it step 4 has nowhere to copy to.

**Steps 4, 4c/4d and 5b are three different jobs, and stopping after the first is the common
mistake.** Materializing restores the *bytes*, the call graph is built from *references*, and
rooting decides what is live. On a component-dispatch image, doing only step 4 leaves live
handlers indistinguishable from dead code: measured at **2.5%** reachable out of steps 0–4,
**49.4%** once 4d has run, and **~80%** with the rest of the pipeline.

Steps 2 and 3 each carry a filter, because the two seed signals fail differently. A prologue
match goes wrong by landing *in a data table*, which an entropy/code-likeness test catches; a
call match goes wrong by inventing a target *from two adjacent words of a numeric table*,
which it does not — such a table is low-entropy and its high bytes are all legitimate opcodes.
Call targets get a **boundary gate** instead: backward linear-sweep resynchronization, which
refuses a "target" that turns out to sit in the middle of a real instruction. Tune via
`-Dc28x.seed.*` (see the script header).

> **Note:** the module disables Ghidra's **"Non-Returning Functions - Discovered"** and **"Shared
> Return Calls"** analyzers by default (via `enableNoReturnAnalysis` / `enableSharedReturnAnalysis` in
> the `.pspec`). On these images those heuristics falsely mark flash→RAM copied functions
> (`.ramfunc`) non-returning and delete their real flash callers. Re-enable per-program in *Analysis
> Options* if you want genuine non-returning detection on a specific image.

See **[docs/C28X_IMAGE_SETUP.md](docs/C28X_IMAGE_SETUP.md)** for the full pipeline — each step's
mechanism and tuning properties, the two copy-table variants, what to do when neither
materializer detects the copy, and the measurements behind the numbers above. To move existing
analysis onto a rebuilt module, see
**[docs/ANALYSIS-MIGRATION.md](docs/ANALYSIS-MIGRATION.md)**.

#### What the setup scripts label

- **F28377D** — `ghidra_scripts/SetupF28377D.java`: the F2837xD peripheral frames + on-chip RAM
  split into its datasheet banks (`M0`/`M1`, `LS0-5`, `D0`/`D1`, `GS0-15`, CLA/CPU MSGRAMs) with
  correct perms, including the D_CAN **CANA/CANB** message RAM. Pass `CPU1` or `CPU2` — CPU1 has
  device-unique peripherals (UPP/XBAR/USBA/DEV_CFG) that are only labeled when the arg matches.
- **F2812** — `ghidra_scripts/SetupF2812.java`: the F281x memory map (SARAM/Flash/OTP/Boot ROM/
  PIE-vect, optional XINTF zones) plus **eCAN-A**, **EV-A/EV-B**, **ADC**, **SCI-A/B**, **SPI-A**,
  **GPIO**, **SysCtrl/PLL/WD**, **PIE**, **CPU timers**, **XINT**, **XINTF**, **CSM**
  field-by-field. Select the `TMS320C28x:LE:32:f2812` language at import for the matching
  volatile-MMIO ranges + F281x vectors.

#### If the image drives the CLA

The pipeline will materialize the Control Law Accelerator's program RAM and then leave it
completely undecoded, because the C28x SLEIGH cannot read a CLA instruction. The signature is
an LS bank that is initialized and mostly non-zero yet holds **zero** instructions and **zero**
functions while its neighbours hold hundreds. The CLA is a separate language
(`TMS320C28x:LE:32:cla`), so its code has to be a separate **program**: `ExportClaProgram` →
import at `-loader-baseAddr 0x8000` → `SetupClaProgram` → `SyncClaLabels` to carry names and
data types between the two. See [docs/C28X_IMAGE_SETUP.md](docs/C28X_IMAGE_SETUP.md).

### Rebuilding the `.sla` (only if you edit the spec)

```sh
"$GHIDRA_INSTALL_DIR/support/sleigh" data/languages/tms320c28x.slaspec
```

## Architectural Quirks

1. **Word-addressable memory.** The smallest addressable unit is **16 bits**, not 8.
2. **Variable-length instructions** (16–64 bits, in 16-bit parcels).
3. **`loc16`/`loc32` addressing field.** One shared 8-bit operand field decodes to all
   addressing modes (Table 5-1, SPRU430F). Modeled as a single shared SLEIGH sub-table,
   parameterized by the `AMODE` context bit (from ST1). AMODE=0 is the compiler default
   and is implemented first.
4. **Overlapping registers.** `ACC=AH:AL`, `XT=T:TL`, `P=PH:PL`, `XARn=ARnH:ARn`.
   Modeled with SLEIGH register sub-pieces.
5. **Status flags / modes** (ST0/ST1: Z N C V OVM SXM TC PM AMODE …). Implemented for the
   common ALU/branch subset; PM shift mode and exotic corners approximated.

## Documentation

- **[docs/DESIGN.md](docs/DESIGN.md)** — why it's built this way; the 5 architectural
  facts, register-space layout, roadmap, and open questions. Read this first.
- **[docs/BUILDING.md](docs/BUILDING.md)** — compile / install / smoke-test, and the
  WSL↔Windows gotchas.
- **[docs/WRITING-INSTRUCTIONS.md](docs/WRITING-INSTRUCTIONS.md)** — the per-instruction
  recipe and the shared `loc16`/`loc32` sub-table plan.
- **[docs/SLEIGH-IDIOMS.md](docs/SLEIGH-IDIOMS.md)** — SLEIGH idioms & gotchas (each
  backed by a real compiler error). Read before writing constructors.
- **[docs/TESTING.md](docs/TESTING.md)** — the disasm regression harness.
- **[docs/C28X_IMAGE_SETUP.md](docs/C28X_IMAGE_SETUP.md)** — the analysis pipeline in full:
  every step above, the startup copy mechanisms, the CLA, and the measurements.
- **[docs/ANALYSIS-MIGRATION.md](docs/ANALYSIS-MIGRATION.md)** — moving existing analysis
  onto an updated module: decode changes only take effect on re-disassembly, so this is a
  fresh import plus replaying the documentation onto it.
- **[docs/EMULATION.md](docs/EMULATION.md)** — running C28x code in Ghidra's emulator, and
  the state modifier that covers what SLEIGH alone cannot.
- **[docs/PCODE-GAPS-METHODOLOGY.md](docs/PCODE-GAPS-METHODOLOGY.md)** — the playbook for
  turning a "won't decompile / `halt_baddata`" report into a verified SLEIGH fix.
- **[docs/WORKTREES.md](docs/WORKTREES.md)** — several branches at once, and the
  one-module-per-Ghidra-install footgun that makes naive worktrees bite.

## Status

Work in progress. Has successfully decoded several firmware images from production hardware. Expect bugs and verify against the TI reference manual or `dis2000` from the TI C28x SDK.

## License

Licensed under the [Apache License, Version 2.0](LICENSE) — the same license Ghidra
itself ships under. See [NOTICE](NOTICE) for the required attribution notices and
[THIRD-PARTY.md](THIRD-PARTY.md) for provenance of TI-derived material.

Apache-2.0 includes an explicit patent grant (§3) and a reciprocal patent-litigation
clause; if you sue any contributor over patents on this software, your grant terminates.
Contributions to this repository are accepted under the same license: opening a pull
request means you agree to license that contribution under Apache-2.0
(**inbound = outbound** — see [CONTRIBUTING.md](CONTRIBUTING.md)).
