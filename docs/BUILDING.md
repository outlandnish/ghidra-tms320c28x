# Building, installing & testing the module

## Requirements

- **Ghidra 12.x** (developed against 12.1.2).
- A JDK matching your Ghidra (Ghidra bundles one, or use your own).
- The reference PDFs to regenerate the large extracted chapters if needed:
  **SPRU430F** (core ISA) and **spruhs1c** (extended ISA — FPU/VCU).

## Compile the SLEIGH spec

The module's language is built by Ghidra's SLEIGH compiler.

```sh
# from a copy of data/languages/ (see the UNC note below if on WSL):
"$GHIDRA_INSTALL_DIR/support/sleigh" tms320c28x.slaspec
```

A clean build prints only `WARN  N NOP constructors found` (harmless — decode-only
constructors with empty bodies look NOP-like to the linter) and possibly
`WARN  N unnecessary extensions/truncations`. **Any `ERROR` line means no `.sla` was
written** — read the FIRST error (later ones often cascade) and consult
`docs/SLEIGH-IDIOMS.md`.

### WSL ↔ Windows gotcha

If you keep the module on a WSL filesystem but run Ghidra on Windows: `cmd.exe` /
`.bat` files **cannot run from a `\\wsl.localhost\…` UNC working directory** ("UNC
paths are not supported"). Ghidra's `sleigh.bat` is a batch file, so copy
`data/languages/` to a Windows-local temp dir, compile there, then copy the resulting
`.sla` back. The build helper in `tests/run_disasm_test.ps1` does this automatically.

## Install into Ghidra

**Option A — drop-in (fastest for iterating):**
Copy the module folder into `<GHIDRA_INSTALL_DIR>/Ghidra/Processors/TMS320C28x/`,
making sure a freshly compiled `tms320c28x.sla` is present in `data/languages/`.
Restart Ghidra (it scans `Processors/` only at startup).

**Option B — packaged extension:**
```sh
gradle -PGHIDRA_INSTALL_DIR=<GHIDRA_INSTALL_DIR>
# produces dist/*.zip -> install via File > Install Extensions, then restart
```

> **Important:** Ghidra caches the compiled `.sla` at startup. After rebuilding the
> spec, a running Ghidra keeps using the OLD language — you must restart Ghidra AND
> re-import the target (an already-imported program is bound to its original
> language; re-analyzing won't pick up new opcodes).

## Smoke test in Ghidra

1. New project, import any raw C28x binary.
2. Language picker: confirm **TMS320C28x** (`TMS320C28x:LE:32:default`) appears.
3. Register Manager: `ACC` shows `AH`/`AL` sub-pieces; `XAR0–7`/`AR` overlaps right.
4. Disassemble bytes `01 00` → `ABORTI`; `21 76` → `IDLE` (little-endian words).

## Re-extracting reference chapters from the PDFs

The large per-instruction reference files are gitignored; regenerate with poppler's
`pdftotext` (note PDF page = printed page + 2 for SPRU430F):

```sh
pdftotext -f 22  -l 53  -layout spru430f.pdf docs/c28x/ch2_cpu_registers.txt
pdftotext -f 81  -l 108 -layout spru430f.pdf docs/c28x/ch5_addressing_modes.txt
pdftotext -f 109 -l 117 -layout spru430f.pdf docs/c28x/ch6_instruction_summary.txt
pdftotext -f 118 -l 474 -layout spru430f.pdf docs/c28x/ch6_instruction_detail.txt
# extended ISA (spruhs1c): FPU registers/instructions, VCU, etc.
```

Grep `ch6_instruction_detail.txt` for an instruction's `Opcode  ....  ....` line to
get its exact bit encoding (e.g. `IDLE` → `0111 0110 0010 0001` = 0x7621).
