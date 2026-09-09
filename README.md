# ghidra-tms320c28x

A Ghidra processor module (SLEIGH) for the Texas Instruments **TMS320C28x** DSP core with initial support for:

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

**Requirements:** Ghidra **12.x** (built against 12.1.2)

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

See **[docs/C28X_IMAGE_SETUP.md](docs/C28X_IMAGE_SETUP.md)** for the full pipeline — each step's
mechanism and tuning properties, the two copy-table variants, what to do when neither
materializer detects the copy, and the measurements behind the numbers above. To move existing
analysis onto a rebuilt module, see
**[docs/ANALYSIS-MIGRATION.md](docs/ANALYSIS-MIGRATION.md)**.

#### CLA support

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
