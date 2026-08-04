# ghidra-tms320c28x

A Ghidra processor module (SLEIGH) for the Texas Instruments **TMS320C28x** DSP core.
Two device targets share one SLEIGH core (the C28x instruction set is common; the
`.sla` is identical):

- **TMS320F28377D** — dual-core C28x + FPU + VCU (F2837xD family). Language
  `TMS320C28x:LE:32:default`; peripherals via `SetupF28377D.java`.
- **TMS320F2812** — the original fixed-point C28x (F281x family; no FPU/VCU/TMU/CLA),
  also covering the memory-compatible F2810/F2811. Language `TMS320C28x:LE:32:f2812`;
  peripherals via `SetupF2812.java`. See [docs/c28x/f2812_memmap.md](docs/c28x/f2812_memmap.md).

> **WIP / vibe-coded.** Verify against the SPRU430F/SPRUHS1C reference
> before trusting any decode for critical work, and please file issues.

## Setup — add this processor to your Ghidra

**Requirements:** Ghidra **12.x** (built against 12.1.2). Nothing else — the repo ships a
prebuilt `data/languages/tms320c28x.sla`, so you don't need to compile anything to use it.

### Install (pick one)

**Option A — drop-in install (simplest).** Copy the module into your Ghidra processors dir
so it loads at startup:

```sh
# Linux / macOS
cp -r ghidra-tms320c28x "$GHIDRA_INSTALL_DIR/Ghidra/Processors/TMS320C28x"
```
```powershell
# Windows (PowerShell)
Copy-Item -Recurse ghidra-tms320c28x "$env:GHIDRA_INSTALL_DIR\Ghidra\Processors\TMS320C28x"
```

The folder must contain `data/languages/` with a compiled `tms320c28x.sla` (it's checked in).
**Restart Ghidra** — it scans `Processors/` only at startup.

**Option B — packaged extension** (installs via the UI, easier to manage/uninstall):

```sh
gradle -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR     # produces dist/*.zip
```
Then in Ghidra: **File ▸ Install Extensions ▸ +**, pick the `dist/*.zip`, and restart.

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

### Analyzing a headerless raw image — recommended script workflow

A raw firmware `.bin` has no symbols or entry points, so Ghidra's analyzer finds almost
nothing. The bundled scripts (Script Manager, category **TMS320C28x**) recover the code and
separate it from the embedded data tables. Run them in this order after **import + set base**:

1. **`SeedFunctions.java`** — create functions from the bytes: absolute **call targets**
   (LCR/LC/FFC, high-confidence — something calls them) plus **prologue patterns**
   (SP-push/frame-setup runs). It also adds call-site→target references (so the call graph
   is visible) and runs an **entropy/code-likeness filter** so prologue matches that land in
   data don't become bogus functions. Reads only initialized memory. Tune via `-Dc28x.seed.*`
   (see the script header).
2. **`MarkJumpTables.java`** — switch/case **pointer tables** (word-pairs forming in-image
   code addresses) get mis-decoded as bogus instructions; this marks them as `pointer` data
   with refs to their targets. Skips runs inside defined functions.
3. **`MarkDataTables.java`** — **float-constant tables** (gain curves, LUTs, calibration)
   likewise decode as garbage; this marks high-confidence (`≥90%` sane-float) runs as
   `Float4` arrays and removes the 0-xref false-seeds they spawned.
4. **`MaterializeSections.java`** — replays the C-runtime startup's flash→RAM section copies
   (`.ramfunc` / `.cinit`) so the **RAM-resident code** the app runs from LS/D/GS RAM becomes real
   and its flash callers resolve. Also marks the flash **load images** back to data (dropping the
   phantom duplicate functions decoded from them).
5. **`FinalizeRamfuncs.java`** — run **after** auto-analysis settles: rebuilds ramfunc bodies that
   were bound before analysis finished decoding them.

See **[docs/C28X_IMAGE_SETUP.md](docs/C28X_IMAGE_SETUP.md)** for the full pipeline, the section-copy
mechanism, and the known ramfunc no-return / flash-truncation caveat (an auto-analysis artifact).

### Optional: label the device peripherals

Pick the script for your target (Script Manager, category **TMS320C28x**) to map the
device memory and label its peripheral frames so XREFs resolve to readable register names:

- **F28377D** — `ghidra_scripts/SetupF28377D.java` (maps the F2837xD frames + on-chip
  RAM, including the D_CAN **CANA/CANB** registers; prompts for CPU1/CPU2).
- **F2812** — `ghidra_scripts/SetupF2812.java` (maps the F281x memory map — SARAM/Flash/
  OTP/Boot ROM/PIE-vect, optional XINTF zones — and labels **eCAN-A**, **EV-A/EV-B**,
  **ADC**, **SCI-A/B**, **SPI-A**, **GPIO**, **SysCtrl/PLL/WD**, **PIE**, **CPU timers**,
  **XINT**, **XINTF**, **CSM** field-by-field). Select the `TMS320C28x:LE:32:f2812`
  language at import for the matching volatile-MMIO ranges + F281x vectors.

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

## Status

Work in progress. Has successfully decoded several firmware images from production hardware. Expect bugs and verify against the TI reference manual or `dis2000` from the TI C28x SDK.
