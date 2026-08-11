# Working on several branches at once with git worktrees

A [git worktree](https://git-scm.com/docs/git-worktree) is a second working
directory backed by the same repository, checked out to a different branch. It
lets you keep, say, the FFC-analyzer branch, the FPU-flags branch, and a
switch-analyzer branch each in its own folder — no stash-dance, no re-clone, one
shared object store and history.

This module has one wrinkle that makes naive worktrees bite, plus a little tooling
to take the wrinkle away.

## The wrinkle: the processor module is a singleton per Ghidra install

Every dev harness installs the built module into **one** shared location —
`$GHIDRA_INSTALL_DIR/Ghidra/Processors/TMS320C28x/` — and then runs headless
Ghidra out of that same install:

- `tests/run_disasm_test.{sh,ps1}` compiles the `.sla` and drops it (plus
  `Module.manifest`) there, then headless-imports a fixture.
- `tests/build_modifier.{sh,ps1}` compiles the Java state modifier and drops the
  jar + pspec there.
- `tests/run_fw_parity.{sh,ps1}` reads whatever `.sla` is installed there.

So if two worktrees both point at the **same** Ghidra, they can't each have their
own spec loaded at the same time — whichever harness ran last wins, and the other
worktree is now silently testing the wrong bytes. This is a correctness footgun,
not just a race: even running them one-at-a-time, the installed module no longer
matches the worktree you think you're in.

There are two ways to live with this, and the tooling supports both:

1. **One Ghidra, test one worktree at a time** (fine for most work). Each worktree
   still builds and installs correctly; just don't expect two headless test runs
   to be valid simultaneously.
2. **A second Ghidra install per worktree** → genuinely parallel headless tests.
   Point each worktree's `.c28x.env` (below) at its own `GHIDRA_INSTALL_DIR`.

> The same singleton applies to an **interactive** Ghidra GUI: it caches the
> compiled `.sla` at startup and binds each imported program to its language, so
> after any rebuild you must restart Ghidra **and re-import**. A GUI can only have
> one worktree's module live at a time — see [docs/BUILDING.md](BUILDING.md).

## Per-worktree config: `.c28x.env`

Rather than exporting `GHIDRA_INSTALL_DIR` (and `C2000WARE`, `JAVA_HOME`) into
every shell, each worktree can carry a **`.c28x.env`** at its root. The harnesses
load it automatically (via `tests/_env.sh` / `tests/_env.ps1`); it is **gitignored**
— it's per-checkout, per-machine config, never committed.

```ini
# <worktree>/.c28x.env   (copy from .c28x.env.example)
GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.2_PUBLIC
# C2000WARE=/opt/ti/ti-cgt-c2000        # run_fw_parity only
# JAVA_HOME=/usr/lib/jvm/temurin-21     # build_modifier only
```

Precedence, highest first:

1. An explicit flag (`-Ghidra` / `-Ti` on the PowerShell harnesses).
2. **`.c28x.env`** in the worktree — a value here *wins* over an inherited shell
   variable, because the point is that a worktree pins its own install.
3. An inherited environment variable (`export GHIDRA_INSTALL_DIR=…`).
4. (build_modifier only) its hard-coded last-resort default.

**No `.c28x.env` present ⇒ behaviour is exactly as before this file existed** —
which is why CI, which has none, is unaffected.

Scratch/temp dirs are also keyed per worktree now: the Windows harnesses used a
fixed `"$env:TEMP\c28x-*"` that two worktrees would corrupt; they now derive a
per-worktree dir (`c28x-<leaf>-<hash>-…`). The bash harnesses already used
`mktemp`.

## The helper: `scripts/worktree.{sh,ps1}`

Wraps `git worktree` and does the `.c28x.env` seeding + collision-checking for you.

```sh
# Linux / macOS / WSL
scripts/worktree.sh add feat/switch-analyzer     # new branch off origin/main, in a sibling dir
scripts/worktree.sh add some/existing-branch      # checks out an existing local/remote branch
scripts/worktree.sh add feat/x ../somewhere       # explicit path
scripts/worktree.sh list                          # worktrees + their pinned Ghidra; warns on shared installs
scripts/worktree.sh env                           # resolved config for the current worktree
scripts/worktree.sh remove ../ghidra-tms320c28x-worktrees/feat-x
```

```powershell
# Windows
pwsh -File scripts\worktree.ps1 add feat/switch-analyzer
pwsh -File scripts\worktree.ps1 list
pwsh -File scripts\worktree.ps1 env
pwsh -File scripts\worktree.ps1 remove <path> -Force
```

`add`:

- Creates the worktree in a sibling `../<repo>-worktrees/<branch>` by default
  (pass an explicit path to override). New branches start from `origin/main` (then
  `main`, then `HEAD`); an existing local or `origin/` branch is checked out as-is.
- **Seeds `.c28x.env`** into the new worktree — copied from the main worktree's
  `.c28x.env` if present, else generated from your current environment, else a
  template you must edit.
- Warns if the new worktree ends up sharing a `GHIDRA_INSTALL_DIR` with another
  (the parallel-test footgun above).

`list` shows each worktree's resolved `GHIDRA_INSTALL_DIR` and prints the same
shared-install warning, so you can see at a glance which worktrees can be tested
independently.

## Removing a worktree

`scripts/worktree.{sh,ps1} remove <path>` calls `git worktree remove` (append
`--force` / `-Force` if it has uncommitted changes). The branch itself is left
alone — delete it separately with `git branch -d <branch>` once merged. Nothing
outside the worktree folder and its (gitignored) `.c28x.env` is touched.
