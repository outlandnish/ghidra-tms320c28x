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

# _c28x_install_module <ghidra-root> <module-root>
#
# Copy data/languages/* and Module.manifest into the ONE location Ghidra actually
# loads the C28x module from, and echo that location's lib/ directory (created) so
# the caller can drop a compiled jar in the right place. Progress goes to stderr so
# stdout carries only the path.
#
# Precedence mirrors tests/_env.ps1's Install-C28xModule: an installed extension
# wins when present, else the $GHIDRA_INSTALL_DIR/Ghidra/Processors/TMS320C28x
# drop-in. Populating BOTH is a bug -- Ghidra 12.1.2 detects the duplicate <language>
# and refuses to start with "Language ... previously defined". The extension used to
# silently shadow the drop-in; it does not any more.
#
# Extensions live under Ghidra's per-user settings dir, which differs by platform and
# has moved between releases, so probe the known roots rather than assume one:
#   $XDG_CONFIG_HOME/ghidra (default ~/.config/ghidra)  -- Ghidra 11+ on Linux
#   ~/.ghidra                                           -- older layout
#   $APPDATA/ghidra                                     -- bash on Windows (Git Bash)
# CI has no extension installed, so it takes the drop-in branch and is unaffected.
_c28x_install_module() {
  local ghidra="$1" module="$2"
  local lang="$module/data/languages"
  local manifest="$module/Module.manifest"
  local ext="" root cand appdata target

  appdata="${APPDATA:-}"
  # Git Bash exports APPDATA as a Windows path; convert when we can, else skip it.
  if [ -n "$appdata" ] && case "$appdata" in *\\*) true ;; *) false ;; esac; then
    if command -v cygpath >/dev/null 2>&1; then
      appdata=$(cygpath -u "$appdata")
    else
      appdata=""
    fi
  fi

  for root in "${XDG_CONFIG_HOME:-$HOME/.config}/ghidra" "$HOME/.ghidra" ${appdata:+"$appdata/ghidra"}; do
    [ -d "$root" ] || continue
    for cand in "$root"/*/Extensions/ghidra-tms320c28x; do
      if [ -d "$cand" ]; then ext="$cand"; break; fi
    done
    [ -n "$ext" ] && break
  done

  if [ -n "$ext" ]; then
    target="$ext"
    printf 'installed to extension: %s\n' "$target" >&2
  else
    target="$ghidra/Ghidra/Processors/TMS320C28x"
    printf 'installed to drop-in: %s\n' "$target" >&2
  fi

  mkdir -p "$target/data/languages" "$target/lib"
  cp "$lang"/* "$target/data/languages/"
  cp "$manifest" "$target/Module.manifest"
  printf '%s\n' "$target/lib"
}
