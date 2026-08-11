# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# Per-worktree config loader (bash). Sourced by the dev harnesses so each git
# worktree can pin its own GHIDRA_INSTALL_DIR / C2000WARE / JAVA_HOME instead of
# relying on globally-exported shell state -- which is what lets two worktrees
# target two different Ghidra installs and not fight over one. See docs/WORKTREES.md.
#
# Reads KEY=VALUE lines from `.c28x.env` at the worktree root. That file is
# gitignored -- it is local machine config, never committed (template:
# .c28x.env.example). A value set in the file WINS over an inherited environment
# variable, because the whole point is that a worktree pins its own install; to
# override for a single run, export before calling or (ps1) pass -Ghidra/-Ti.
#
# Absent file => no-op => behaviour identical to before this loader existed. That
# is why CI, which has no .c28x.env, is completely unaffected.
#
# Format: KEY=VALUE per line; blank lines and `#` comments ignored; values may
# contain spaces and backslashes (no quoting needed) and a trailing CRLF is
# tolerated so a Windows-edited file still parses under WSL.

# _c28x_load_env <worktree-root>
_c28x_load_env() {
  local root="$1" f line k v
  f="$root/.c28x.env"
  [ -f "$f" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    # strip leading whitespace (also drops a leading CR on a blank CRLF line)
    line=${line#"${line%%[![:space:]]*}"}
    case "$line" in
      '' | \#*) continue ;;   # blank / comment
      *=*) ;;                 # a KEY=VALUE line
      *) continue ;;          # anything else: ignore
    esac
    k=${line%%=*}
    v=${line#*=}
    k=${k%"${k##*[![:space:]]}"}   # trim trailing whitespace from the key
    v=${v%$'\r'}                   # tolerate a Windows CRLF line ending
    [ -n "$k" ] || continue
    export "$k=$v"
  done < "$f"
  return 0   # never let read's EOF non-zero abort a `set -e` caller
}
