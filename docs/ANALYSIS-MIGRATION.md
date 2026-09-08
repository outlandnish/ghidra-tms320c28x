# Migrating existing analysis onto an updated SLEIGH module

Decode and analyzer changes only take effect on **re-disassembly**, so programs analysed on an
older module cannot benefit from them. A full clear-and-re-disassemble in place loses more than
it saves (it discards the seeding and materialization the pipeline did), so the migration is a
**fresh import + full pipeline + replay the documentation onto it**.

This is the runbook for that. It assumes `docs/C28X_IMAGE_SETUP.md` for what the pipeline steps
mean; this file only covers moving *existing analysis* across.

## When it is worth doing

| change | needs re-import? |
|---|---|
| new/corrected instruction decode | **yes** — the listing is wrong until re-disassembled |
| p-code semantics (flags, call model) | **yes** for emulation and the decompiler |
| a new or fixed analyzer | **yes** — analyzers run at import |
| cspec / calling conventions | partly: bound at load, but signatures only settle on re-analysis |
| assembler-only fixes | no |

## Order matters, because of the project lock

Headless takes an **exclusive** project lock; the GUI takes a shared one. So:

- read-only headless (`-readOnly`) works while the GUI is open,
- **writing headless requires Ghidra closed**, and two headless runs cannot overlap,
- the MCP bridge needs the GUI open.

The phases below are ordered so you close Ghidra once and reopen it once.

---

## Phase 0 — export the annotations (GUI open or closed)

The safety net. Do it first, before anything is imported, renamed or deleted.

```
ExportAnnotations <outDir> gdt          # per program, or:
ExportAnnotations <outDir> batch TMS320C28x gdt
```

Writes `<projectpath>.annotations.json` plus a `.gdt` type archive per program. Keep it outside
the project (and somewhere private if the images are). Nothing later in this runbook can lose
work that is captured here.

## Phase 1 — recover the source images (read-only, GUI may stay open)

> Phases 1 and 2 are one-time. Once the dumps and the content-matched provenance mapping are
> kept somewhere durable, later migrations reuse them and start at Phase 3.

You need the original `.bin` for each program. Staged copies go missing, and rebuilding one from
its original packaging is **unsafe** when several releases ship a file with the same name.

Dump it out of the program instead — byte-exact by construction:

```
DumpFlashImage <outDir>
```

Validate the technique once against a staged image that did survive (`sha256sum` must match),
then trust it for the rest.

Two traps it already handles:

- **The image base is not a reliable handle.** A program imported at base 0 and then given
  `set_image_base` on the block only still reports `getImageBase() == 0`, and a RAM bank
  genuinely starts there. So the rule is "largest initialized block in the flash window", not
  "block at the image base".
- **`currentProgram.getName()` is not the project file name.** A program renamed in the project
  tree keeps its original internal name. Key output files off
  `getDomainFile().getName()`.

## Phase 2 — pin the provenance before renaming anything

Match every dumped image back to its original packaged artifact **by content**, not by filename.
Filenames drift and get reused; content does not. Expect a fixed header offset between the two.

Do this even if you are not renaming: on the last migration it showed that folder names had
drifted badly from what the images actually were (a folder labelled with one release held
another's build; a folder named for one hardware generation held a different one; one folder
conflated four distinct variants). Record the result — that mapping is the most reusable thing
the migration produces.

If you rename, put **release + variant** in the folder name so provenance survives the next
round, and keep the paired ECUs of one variant together.

## Phase 3 — import and pipeline (Ghidra CLOSED)

Two headless passes per program, because the pipeline needs auto-analysis to run in the *middle*
of it and headless only runs analysis between pre- and post-scripts:

```
pass A   -import <bin> -loader BinaryLoader -loader-baseAddr <base> \
         -processor TMS320C28x:LE:32:default -noanalysis -overwrite
         SetupF28377D <CPU> -> SeedFunctions -> MarkJumpTables -> MarkDataTables
         -> MaterializeSections -> MaterializeCopyTable -> EmulateStartup apply

pass B   -process <name>                    (auto-analysis runs here)
         MarkComponentRegistry -> FinalizeRamfuncs -> MergeSplitFunctions
         -> FinalizeRamfuncs -> RetypeWideMemory -> ReachabilityReport
```

Stage each dump under the **target program name** first — headless names the program after the
file it imports.

### The second migration collides with itself

The first migration is safe because it *renames*: the new programs land at new paths, so the old
ones are still there to merge from. Every migration after that starts from names the previous one
already made canonical — so the import target **is** the program it supersedes, and `-overwrite`
destroys the analysis before Phase 4 can read it.

Move the old ones aside first, then import into the freed names:

```
RenamePrograms <listFile> [apply]     # "projectPath|newName" per line, dry run by default
```

Suffix with the module state they came from (`__pre115`), not `_old` — after two rounds you want
to know *which* module a leftover was analysed on. Phase 6 then deletes the suffixed ones.

Rename **before** importing but **after** exporting annotations, so the exported files are keyed
to the canonical paths the new programs will occupy.

**Install the language and the modifier jar as a matched pair from the same commit**, and run
`run_disasm_test`, `run_phase_check` and `run_emu_test` before starting. A jar from a different
commit than the `.sla` fails in ways that look like image problems.

**`-scriptPath` does not necessarily win.** Ghidra may resolve scripts from
`$USER_HOME/ghidra_scripts` instead. Diff that directory against the repo before a batch run, or
you will pipeline 20 images with a stale script.

### Pilot one image first

Run a single image end to end and read the log before committing hours. Check the startup replay
reached the application handoff, the copy routine was found, and the function count is within a
few percent of the old program. A startup replay that does **not** hand off is the loud failure
mode — see below.

## Phase 4 — replay the documentation (Ghidra OPEN, over MCP)

**Run both tools, in this order.** They are not redundant:

```
merge_program_documentation(source=<old>, target=<new>)    # bulk, address-exact
ImportAnnotations <exported.json> apply                    # rehomes what moved
```

`merge_program_documentation` is **address-exact**: it applies only where a function starts at
exactly the recorded address, and silently skips the rest. That is fine for data and comments,
but the new pipeline seeds function entries slightly differently (split-function merges, a
stricter boundary gate), so entries that moved by a word or two are dropped **without being
reported**.

`ImportAnnotations` handles exactly that case: it **rehomes** a record to the function that now
*contains* the recorded address, notes the correction in the plate comment, and reports anything
genuinely missing. Measured on one image last round:

| | merge only | + ImportAnnotations |
|---|---|---|
| documented functions | 168 | **213** (source had 214) |
| function names applied | 202 | 250 exact + 9 rehomed |
| data typed | 328 | 1134 |

Neither tool clobbers an existing name, so running them in this order is safe and additive, and
a name already applied by the merge is left alone rather than reported as a conflict.

**When two old programs hold analysis of the same bytes**, merge both into one new program,
**richest source first** — both tools are first-writer-wins. Check which is richer with the
export counts rather than assuming; the newer folder is not always the better analysis.

Ignore `IMAGE BASE DIFFERS` from `ImportAnnotations` when the counts show everything landing:
it compares `getImageBase()`, which reads 0 for programs imported via `-loader-baseAddr` even
though the blocks are placed correctly.

## Phase 5 — verify before deleting anything

For each new program compare **documented function count** against the old one
(`compare_programs_documentation`). It should be equal or higher. Then account for every
shortfall:

- **collision** — target kept its name, export name added as a secondary label. Nothing lost.
- **rehomed** — applied to the corrected entry. Nothing lost.
- **missing** — genuinely absent. Read each one; a handful is normal (an address that is no
  longer a function, or a peripheral label rather than code), a lot is a pipeline problem.

Also compare total function count against the old program — within a few percent. A large drop
means tail-marking ate flash code; check the copy-table classification first.

## Phase 6 — delete (Ghidra closed, or `delete_file` over MCP)

Only after Phase 5 passes.

```
DeleteOldPrograms <listFile> [apply]      # explicit paths, dry run by default
RemoveEmptyFolders <listFile> [apply]     # allow-listed, dry run by default
```

Both take an **explicit list** rather than a pattern, so what is removed is reviewable before
and auditable after. A program still open in a tool refuses to delete; close it and retry.

On a re-migration this is the `__pre<n>` set renamed aside in Phase 3, and the folders are
already correct — so there is usually nothing for `RemoveEmptyFolders` to do.

Removing folders the deletion emptied is part of the job. Removing folders that were *already*
empty is the project owner's call, not a side effect — hence the allow list.

---

## The failure mode to watch for: a startup replay that never finishes

`EmulateStartup` replays the image's own `_c_int00` and keeps the RAM it writes. If it does not
reach the application handoff, the RAM state is partial at best, and if it is spinning the write
set is a few regions rewritten thousands of times. **Materializing that is far worse than
materializing nothing**, because the garbage then feeds disassembly and the reference graph.

It now refuses to apply unless the replay stopped cleanly, prints the hottest addresses, and
names the `-Dc28x.emu.skip` that steps over the enclosing function. Read that output — a tight
cluster of two or three addresses **is** the loop it never left.

Two causes, and they need opposite responses:

- **A peripheral poll** (`TBIT` on an MMIO status bit, then a conditional branch back) waits on
  hardware the emulator does not model. Unfixable by emulation; skip it, or accept that image
  will not get a startup replay. It still gets the whole rest of the pipeline.
- **A count loop that never terminates** is usually **our bug**, not the firmware's. If a
  decrement-and-branch never exits, suspect the decrement is not setting the flag the branch
  reads. That is exactly what a missing flag write in the SLEIGH body looks like, and decode
  parity is structurally blind to it because the mnemonic and operands are correct either way.
  This has now been found three times (`ADDB ACC,#8bit`, then `SUBB`/`SUBU ACC`). Before
  reaching for `-Dc28x.emu.skip`, check the loop's terminating instruction against SPRU430F.

Symptoms of the second, from the last migration: the replay burned its whole step budget, wrote
666,662 words (more RAM than the device has), and the finished program came out at 8.2%
reachability instead of ~79%. Fixing the SLEIGH took the same image to a clean handoff in 71,964
steps and 21,453 words.

## Checklist

- [ ] Phase 0 — annotations + `.gdt` exported for every program in scope
- [ ] Phase 1 — sources dumped; technique validated against one known-good staged image
- [ ] Phase 2 — provenance pinned by content; mapping recorded
- [ ] re-migration only: old programs renamed aside, so the import cannot overwrite them
- [ ] language + jar installed as a matched pair; disasm / phase / emu suites pass
- [ ] `$USER_HOME/ghidra_scripts` diffed against the repo
- [ ] Phase 3 — pilot one image, read the log, then batch
- [ ] every image reached the startup handoff (or is a known, understood refusal)
- [ ] Phase 4 — merge **then** ImportAnnotations, richest source first
- [ ] Phase 5 — documented counts equal or higher; every shortfall accounted for
- [ ] Phase 6 — delete from an explicit list, then the folders it emptied
