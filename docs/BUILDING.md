# Building, installing & testing the module

## Requirements

- **Ghidra 12.x** (developed against 12.1.2).
- A JDK matching your Ghidra (Ghidra bundles one, or use your own).

## Compile the SLEIGH spec

```sh
"$GHIDRA_INSTALL_DIR/support/sleigh" data/languages/tms320c28x.slaspec
```

A clean build prints only `WARN  N NOP constructors found` (decode-only constructors
with empty bodies look NOP-like to the linter) and possibly
`WARN  N unnecessary extensions/truncations`. **Any `ERROR` line means no `.sla` was
written** — read the FIRST error (later ones cascade) and consult
[SLEIGH-IDIOMS.md](SLEIGH-IDIOMS.md).

### WSL ↔ Windows

If the module lives on a WSL filesystem but Ghidra runs on Windows: `cmd.exe` /
`.bat` files **cannot run from a `\\wsl.localhost\…` UNC working directory**. Copy
`data/languages/` to a Windows-local temp dir, compile there, copy the `.sla` back.
`tests/run_disasm_test.ps1` does this automatically.

## Install into Ghidra

**Option A — packaged extension:**
```sh
gradle -PGHIDRA_INSTALL_DIR=<GHIDRA_INSTALL_DIR>
# produces dist/*.zip -> install via File > Install Extensions, then restart
```

**Option B — drop-in:**
Copy the module folder into `<GHIDRA_INSTALL_DIR>/Ghidra/Processors/TMS320C28x/`
with a freshly compiled `tms320c28x.sla` in `data/languages/`. Restart Ghidra
(it scans `Processors/` only at startup).

> **Ghidra caches the compiled `.sla` at startup.** After rebuilding, a running
> Ghidra keeps using the OLD language — restart Ghidra AND re-import the target
> (already-imported programs are bound to their original language; re-analyzing
> doesn't pick up new opcodes).

## Smoke test

1. Import any raw C28x binary.
2. Language picker: confirm `TMS320C28x:LE:32:default` appears.
3. Register Manager: `ACC` shows `AH`/`AL` sub-pieces; `XAR0–7`/`AR` overlaps right.
4. Disassemble `01 00` → `ABORTI`; `21 76` → `IDLE` (little-endian words).

## Re-extracting reference chapters from the PDFs

The large per-instruction reference files under `docs/c28x/` are gitignored;
regenerate from the two source manuals — **SPRU430F** (core ISA) and **spruhs1c**
(FPU/VCU/TMU) — with poppler's `pdftotext` (PDF page = printed page + 2 for
SPRU430F):

```sh
pdftotext -f 22  -l 53  -layout spru430f.pdf docs/c28x/ch2_cpu_registers.txt
pdftotext -f 81  -l 108 -layout spru430f.pdf docs/c28x/ch5_addressing_modes.txt
pdftotext -f 109 -l 117 -layout spru430f.pdf docs/c28x/ch6_instruction_summary.txt
pdftotext -f 118 -l 474 -layout spru430f.pdf docs/c28x/ch6_instruction_detail.txt
```

Grep `ch6_instruction_detail.txt` for an instruction's `Opcode  ....  ....` line to
get its bit encoding (e.g. `IDLE` → `0111 0110 0010 0001` = 0x7621).
