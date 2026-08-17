# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A Ghidra 12.x processor module (SLEIGH) for the TI **TMS320C28x** DSP core. One `.sla` decodes the superset ISA (C28x core + FPU + VCU + TMU); device targets are `.pspec` + `Setup*.java` pairs layered on top. Current device targets: **F28377D** (language `TMS320C28x:LE:32:default`) and **F2812** (`TMS320C28x:LE:32:f2812`).

Read [docs/DESIGN.md](docs/DESIGN.md) first — the address-space model, register layout, and addressing sub-tables are load-bearing and easy to break.

## Build / test loop

```sh
# Compile the SLEIGH spec (writes data/languages/tms320c28x.sla)
"$GHIDRA_INSTALL_DIR/support/sleigh" data/languages/tms320c28x.slaspec

# Package as an installable Ghidra extension zip
gradle -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR   # writes dist/*.zip

# Regression harnesses (all headless; each rebuilds .sla + reinstalls into $GHIDRA_INSTALL_DIR)
tests/run_phase_check.sh                          # RPT phase-bit invariant; no Ghidra, no compile
tests/run_disasm_test.sh                          # mnemonic decode parity, 4 fixture suites
tests/build_modifier.sh                           # compile Java emulator/state-modifier jar
tests/run_emu_test.sh                             # FPU flags, FPU conditioning, RPT/RPTB loops
                                                  # (requires build_modifier first)
tests/run_fw_parity.sh -Fw <swapped.bin> -Start 0xNNN -Count 0xNN [-Base 0x82000]
                                                  # dis2000 ground-truth vs our .sla over a word range
```

`run_phase_check` is pure text over `data/languages` — it runs first in CI and fails in seconds.
See "Adding an instruction constructor" for the invariant it guards.

Windows: PowerShell equivalents `run_disasm_test.ps1` / `run_emu_test.ps1` / `run_fw_parity.ps1` / `build_modifier.ps1`.

**Ghidra caches the compiled `.sla` at startup**, and every imported program is bound to the language it was imported under. After any spec rebuild: **restart Ghidra AND re-import the target** — re-analyzing an existing program will keep using the OLD `.sla`.

## Runtime env — `.c28x.env` (per-worktree)

The harnesses source `tests/_env.{sh,ps1}`, which loads a **`.c28x.env`** at the worktree root. It's gitignored (per-checkout, per-machine). Values here **win over** inherited shell vars — the whole point is that a worktree pins its own install.

```ini
GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.2_PUBLIC
# C2000WARE=/opt/ti/ti-cgt-c2000     # only run_fw_parity uses it
# JAVA_HOME=/usr/lib/jvm/temurin-21   # only build_modifier uses it
```

No `.c28x.env` present ⇒ behavior is identical to before this file existed (CI relies on this).

## Worktrees — one Ghidra is a **singleton per install**

Two worktrees sharing one Ghidra can't each have their own spec loaded at once — the last harness to run wins, and the other worktree is silently testing the wrong bytes. Use `scripts/worktree.{sh,ps1}` (documented in [docs/WORKTREES.md](docs/WORKTREES.md)) which warns on shared installs and seeds `.c28x.env`. For genuine parallel testing, point each worktree's `.c28x.env` at a **separate** Ghidra install.

**Install location — populate exactly one.** Ghidra 12.1.2 refuses to start with two modules
defining the same language (`ERROR Language TMS320C28x:LE:32:default previously defined`). The
PowerShell harnesses route through `Install-C28xModule` (`tests/_env.ps1`), which picks the
installed extension under `$APPDATA/ghidra/*/Extensions/ghidra-tms320c28x` when present and falls
back to the `$GHIDRA_INSTALL_DIR/Ghidra/Processors/TMS320C28x/` drop-in otherwise. The **bash**
harnesses still write the drop-in unconditionally, so if you have the extension installed on
Linux, delete one or you will hit the duplicate. A leftover drop-in from before this change keeps
triggering it until removed; its contents are wholly regenerable.

**The `.sla` and the modifier jar are a matched pair.** `run_disasm_test` installs only
`data/languages/*`; `build_modifier` compiles only the Java. Switching branches can leave a jar
built from a *different* worktree, and nothing reports it. That matters most for RPT: the current
`.sla` expects `postExecuteCallback` to drive RPT alone, so an older jar double-drives it and a
jar predating the wrappers doesn't drive it at all. Check with
`javap -cp <jar> ghidra.program.emulation.TMS320C28xEmulateInstructionStateModifier`.

## WSL ↔ Windows gotchas

- **Ghidra on Windows can't run from `\\wsl.localhost\…` UNC** — `sleigh.bat` fails. `run_disasm_test.ps1` copies `data/languages/` to a Windows-local temp dir and copies the resulting `.sla` back.
- **`sleigh.bat` pauses "Press any key" on error**; in PowerShell pipe empty input: `$null | & "$G\support\sleigh.bat" foo.slaspec`.
- **TI toolchain (`cl2000.exe`, `dis2000.exe`, etc.) invoked from bash** fails to spawn its child tools (`acia2000`, `cg2000`, `asm2000`). Route through `cmd.exe /c "set PATH=...&&cl2000.exe ..."` so Windows resolves the child processes.

## The five architectural facts (see [docs/DESIGN.md](docs/DESIGN.md))

1. **Word-addressable memory** — the "byte" is 16 bits (`wordsize=2` on `ram`). Break this and every peripheral XREF lands at half or double the right place.
2. **Variable-length instructions** in 16-bit parcels, little-endian.
3. **One shared `loc16`/`loc32` addressing sub-table** (SPRU430F Table 5-1) parameterized by the `ctx_AMODE` context variable. Implement AMODE=0 first (compiler default).
4. **Overlapping registers** modeled with SLEIGH sub-pieces: `ACC=AH:AL`, `XT=T:TL`, `P=PH:PL`, `XARn=ARnH:ARn`. Register-space offsets in [docs/DESIGN.md](docs/DESIGN.md) table.
5. **Unified `ram` space** (not split CODE/DATA). Splitting breaks the decompiler with *"X may not be a global space"*.

Consequence: when adding a new addressing-mode row in `loc16`/`loc32`, every constructor in that table must export the same byte size (loc16 → all size 2, loc32 → all size 4). See [docs/SLEIGH-IDIOMS.md](docs/SLEIGH-IDIOMS.md) §3.

## Adding an instruction constructor

Per-instruction recipe is in [docs/WRITING-INSTRUCTIONS.md](docs/WRITING-INSTRUCTIONS.md). SLEIGH idioms that produce specific compiler errors (each documented with the exact `Error: …` message) are in [docs/SLEIGH-IDIOMS.md](docs/SLEIGH-IDIOMS.md) — **read those before writing constructors**; the compiler errors are cryptic and non-local.

**Every top-level `:MNEMONIC` constructor must carry `& rpt_phase=1`.** RPT/RPTB are modeled as
`:^instruction` prefix wrappers (`tms320c28x_rpt.sinc`) which gate on `rpt_phase=0`; a wrapper
compiles to a variant of *every* base constructor, so without the opposing phase constraint the
two are indistinguishable and the resolver picks the base — the wrapper silently becomes a no-op.
Omitting it does **not** fail any decode test: the listing is correct, and the only symptom is
that `RPT || <your instruction>` executes once instead of N+1 times. `tests/run_phase_check.{sh,ps1}`
is the guard; run it after adding constructors.

Instruction families are split across `data/languages/tms320c28x_{mov,flow,alu,mac,ext56,more,fpu,vcu}.sinc`, all included from `tms320c28x.sinc`. The shared addressing sub-table lives in `tms320c28x_addr.sinc`.

## Testing bar

- **`run_disasm_test`**: fixture-based decode parity. A constructor isn't done until its known-encoding bytes disassemble to the expected text.
- **`run_fw_parity`**: **0 wrong decodes** on real firmware. A wrong decode is a spec bug. Length skew (a multi-word instr decoded as 1 word) desyncs the entire downstream sweep — the harness flags these separately.
- **Mnemonic parity is not enough** — it compares only the first token. Spot-check operand values after any spec change; see [docs/TESTING.md](docs/TESTING.md) §"What parity does NOT prove" for the four bug classes to watch for (relative-vs-absolute branch targets, partial sub-register writes, wrong token-field bit ranges, wrong multi-word lengths).
- **`run_emu_test`** is the only test that catches wrong bit order *inside* a mask — its bit-split fields render as plausible mnemonics even when swapped.

## Firmware-image workflow

Raw `.bin` images have no symbols; auto-analysis alone finds almost nothing. Ordered scripts in `ghidra_scripts/` (Script Manager category **TMS320C28x**) recover code and separate embedded data tables — run **after import + set base**:

1. `SeedFunctions.java` — seeds from LCR/LC/FFC call targets + prologue patterns (entropy/code-likeness filtered).
2. `MarkJumpTables.java` — switch/case pointer tables (word-pairs) that would decode as bogus instructions.
3. `MarkDataTables.java` — float-constant tables (≥90% sane-float) marked as `Float4[]`.
4. `MaterializeSections.java` — replays the C-runtime flash→RAM `.ramfunc`/`.cinit` copies so RAM-resident code becomes real (the memcpy-const form).
4b. `MaterializeCopyTable.java` — the other startup form: a TI copy table walked by `__TI_auto_init`, either RAW `{load,run,size,flags}` or LZSS-compressed. Auto-detects; a no-op when absent. Which form an image uses is per-core, not per-family — one device's CPU2 can use the table while its CPU1 uses memcpy-const.
5. `FinalizeRamfuncs.java` — after auto-analysis settles, rebuilds ramfunc bodies bound before analysis finished. Run it **again** after any `merge_program_documentation`: a merge can copy a stale no-return flag and re-truncate functions.

Ghidra's **"Non-Returning Functions - Discovered"** and **"Shared Return Calls"** analyzers are disabled by default in the pspec — they falsely mark `.ramfunc` bodies non-returning and delete their real flash callers. Re-enable per-program in Analysis Options only if genuinely needed.

Full pipeline (section-copy mechanism, no-return opt-out, base-address rules): [docs/C28X_IMAGE_SETUP.md](docs/C28X_IMAGE_SETUP.md).

## Reference chapters (`docs/c28x/`)

`docs/c28x/*.txt` are `pdftotext -layout` extractions of **SPRU430F** (core ISA) and **spruhs1c** (FPU/VCU/TMU) chapters. They're **gitignored** — regenerate with the exact page ranges in [docs/BUILDING.md](docs/BUILDING.md) §"Re-extracting reference chapters". Grep them for instruction encodings; each page has an `Opcode  ....  ....` line, and operand-field letters map to token sub-fields.

## Address / word-vs-byte trap

In this `wordsize=2` space, Ghidra's `Address.getOffset()` returns a **byte** offset (word × 2), while TI's `dis2000` prints **word** addresses. Divide by 2 when comparing the two — this bites every script that walks the listing.

## Stack-local rendering (`*-SP[n]`)

Half of the fix ships here: `tms320c28x_addr.sinc` builds stack addresses in SP's native width **inside** the zext (`zext(SP − n)`, not `zext(SP) − n`) so a downstream decompiler fold rule can peel the ZEXT. The other half is a decompiler patch on the `dieseld23/ghidra` `fold-zext-spacebase` branch (NSA/ghidra #2749). Stock Ghidra still renders `ZEXT24(&stack…) − n` in local accesses — annoying, not wrong. **When authoring p-code injection / call-fixups: build stack addresses in the stackpointer's native width inside the zext**, or you defeat spacebase folding on every narrow-SP target.

## Provenance / license

Apache-2.0 (same as Ghidra). Portions of the `.cspec` and some scripts are adapted from `mwdmwd/ghidra-c28x` — see `THIRD-PARTY.md`. TI-derived text (register/instruction descriptions) is used under fair-use for identification; do not paste large blocks of the reference manuals into new files.
