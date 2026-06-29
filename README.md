# ghidra-tms320c28x

A Ghidra processor module (SLEIGH) for the Texas Instruments **TMS320C28x** DSP core,
targeting the **TMS320F28377D** (dual-core C28x + FPU, F2837xD family)..

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

### Loading a raw firmware image — the two things that bite everyone

This is a **word-addressable** architecture (1 address = 16 bits, not 8). Two consequences
when you import a raw `.bin`:

- **Set the image base.** Raw binaries import at base `0`; set it to the image's real load
  address (**Memory Map ▸ edit the block**, or `set_image_base` if scripting) or every
  absolute reference (peripheral registers, string pointers, branch targets) lands wrong.
- **Byte order.** Some vendor flash dumps store the instruction stream **byte-swapped**. If
  a known function decodes to garbage but the bytes "look" right, try a 16-bit byte-swap of
  the image first. (TI-toolchain `.out`/COFF objects are already in the right order.)

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
   (see the script header). `FindEntryPoints.java` is the read-only companion that just
   *ranks* candidates.
2. **`MarkJumpTables.java`** — switch/case **pointer tables** (word-pairs forming in-image
   code addresses) get mis-decoded as bogus instructions; this marks them as `pointer` data
   with refs to their targets. Skips runs inside defined functions.
3. **`MarkDataTables.java`** — **float-constant tables** (gain curves, LUTs, calibration)
   likewise decode as garbage; this marks high-confidence (`≥90%` sane-float) runs as
   `Float4` arrays and removes the 0-xref false-seeds they spawned. Conservative — it skips
   any run overlapping a *referenced* function, so it won't clobber code.

Both `Mark*` scripts support `-D...dryRun=true` to preview before changing anything. Together
they turn a wall of red `halt_baddata` blocks into clean code + typed data tables.

> Why the data scripts matter: C28x firmware interleaves large float/pointer tables with code.
> A seed scan inevitably lands a few false functions in them (a float word can even look like a
> call opcode), so marking the tables as data is what makes the result clean. See the
> per-script headers for the exact heuristics and their limits.

### Optional: label the F2837xD peripherals

Run `ghidra_scripts/SetupF28377D.java` (Script Manager) to map and label the F2837xD
peripheral frames — including the D_CAN **CANA/CANB** registers — so XREFs to them resolve
to readable names. Useful for CAN-firmware RE.

### Rebuilding the `.sla` (only if you edit the spec)

The prebuilt `.sla` is checked in, so most users skip this. If you modify a `.sinc`:

```sh
"$GHIDRA_INSTALL_DIR/support/sleigh" data/languages/tms320c28x.slaspec
```
A clean build prints only `WARN  N NOP constructors found` (harmless). **Any `ERROR` = no
`.sla` written.** Ghidra caches the `.sla` at startup, so after rebuilding you must **restart
Ghidra and re-import** the target (re-analyzing a loaded program keeps the old language). See
[docs/BUILDING.md](docs/BUILDING.md) for the full loop and the WSL↔Windows `sleigh.bat` gotcha.

## Goal

A practical reverse-engineering processor module — decode-complete and decompilable,
not a cycle-accurate model:

- **Decode-complete** core C28x + FPU + VCU instructions (everything disassembles).
- **Real p-code semantics** on the common subset: loads/stores in every addressing
  mode, MOV/ALU/compare/branch/call, and MAC. This makes XREFs to peripheral
  registers resolve and the decompiler produce useful output.
- **FPU / VCU instructions decode-only** (disassemble, minimal semantics) — FP math
  and hardware CRC rarely need full modeling for control-flow RE.
- Includes a **peripheral-labeling script** (`ghidra_scripts/SetupF28377D.java`) that
  maps + labels the F2837xD peripheral frames (incl. the D_CAN CANA/CANB registers).

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

Compiles clean against Ghidra 12.1.2's SLEIGH compiler and decompiles C28x code.
The full instruction set across all families decodes, the shared `loc16`/`loc32`
addressing sub-tables are implemented (AMODE=0), and the decompiler produces C output.

**Validation (TI ground truth):** disassembled five objects from TI's own
`rts2800_fpu32.lib` runtime (real TI-compiled C28x code) and diffed mnemonics against
TI's `dis2000`: **100% agreement, 0 wrong decodes** across all objects (`k_expf`,
`catrigf`, `c99_complex`, `memcpy_s`, `strcpy_s`). The harness is
[tests/run_ti_parity.ps1](tests/run_ti_parity.ps1) +
[ghidra_scripts/DumpParity.java](ghidra_scripts/DumpParity.java) — reuse it for any
TI object.

**Validation (real firmware — decompilation).** Beyond the TI runtime, the module was
hardened against real F28377D production images (both the CAN/PM and the motor-control/DI
halves) by sweeping every function for decompiler truncations (`halt_baddata`) and fixing
the missing/buggy opcode behind each. After this pass, those images decompile with **zero
real-code truncations** — the only residual `halt_baddata` are false functions that a
prologue-pattern seed scan places on data tables (zero xrefs), not code gaps. This drove
the bulk of the opcode set beyond what the TI runtime exercises: the full `0x56`-prefix
extended-math family (MIN/MAX, CMP64/NEG64, 64-bit `ACC:P` shifts by T, QMPYL/QMPYUL,
ADDCL/SUBBL, ABSTC/NEGTC, …), the `SBF` short-branch family, `RPTB` block-repeat, the
`0xE2`/`0xE6` FPU mem-move + conversion families (incl. the round `…16R` variants),
status/mode ops with flow-preserving p-code, and many core loc-form ALU ops.

**Validation (corruption check — differential vs dis2000).** A whole-image differential
disassembly against TI's `dis2000` (~134K instructions on one image) checks not just *that*
a word decodes but that it decodes to the **right length**. A wrong word-count constructor
is the dangerous failure mode — it silently desyncs everything after it, with no visible
truncation. The sweep currently reports **zero instruction-length mismatches** (one such
bug — a mis-encoded `MAX AX,loc16` that claimed `FLIP` and over-consumed a word — was found
this way and fixed). The remaining mnemonic-only differences are benign: dis2000's `||`
parallel-execution prefix, and a handful of TMU trig ops (`DIVF32`/`SINPUF32`/…) we currently
fall back to the generic `0xE2` `MOV32` for (same length, approximate semantics).

Note: parity (mnemonic + length) still does **not** prove full operand/semantics
correctness. Several operand bugs were caught by cross-checking the manual and dis2000, so
keep auditing. See [docs/TESTING.md](docs/TESTING.md) for the parity harness and the
bug classes it can't catch. **When in doubt about any decode, run the word through `dis2000`
— it is the ground-truth oracle and has repeatedly been right where a manual grep was wrong.**
