#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# git-worktree helper for this module. Wraps `git worktree` and, crucially, seeds
# each new worktree's per-worktree config (.c28x.env) so the dev harnesses target
# the right Ghidra -- and warns when two worktrees pin the SAME Ghidra install,
# which cannot run headless tests in parallel (the processor module is a singleton
# within one Ghidra install). See docs/WORKTREES.md.
#
# Usage:
#   scripts/worktree.sh add <branch> [path]   create/checkout a worktree + seed .c28x.env
#   scripts/worktree.sh list                  list worktrees + their pinned GHIDRA_INSTALL_DIR
#   scripts/worktree.sh remove <path>         git worktree remove <path>  (add --force if dirty)
#   scripts/worktree.sh env [path]            print resolved config for a worktree (default: cwd)
#   scripts/worktree.sh help

set -euo pipefail

self=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# The env-parser the harnesses use, so `env`/`list` resolve .c28x.env identically.
. "$self/../tests/_env.sh"

die()  { echo "error: $*" >&2; exit 1; }
warn() { echo "warning: $*" >&2; }

# Absolute path to the MAIN worktree (the one holding the shared .git), regardless
# of which worktree we were invoked from.
main_root() {
  local common
  common=$(git rev-parse --git-common-dir 2>/dev/null) || die "not inside a git repository"
  case "$common" in /*) ;; *) common="$PWD/$common" ;; esac
  (cd "$common/.." && pwd)
}

# Resolve one KEY as the harnesses would for a given worktree (.c28x.env wins, else
# the ambient environment). Run in a subshell so we do not pollute this process.
env_value() {  # <worktree-root> <KEY>
  ( _c28x_load_env "$1"; eval "printf '%s' \"\${$2-}\"" )
}

# Print every worktree as "path<TAB>branch<TAB>ghidra" (branch may be "(detached)").
worktree_rows() {
  local path="" branch=""
  git worktree list --porcelain | while IFS= read -r line; do
    case "$line" in
      "worktree "*) path=${line#worktree } ;;
      "branch "*)   branch=${line#branch refs/heads/} ;;
      "detached")   branch="(detached)" ;;
      "")           [ -n "$path" ] && printf '%s\t%s\t%s\n' "$path" "${branch:-(detached)}" "$(env_value "$path" GHIDRA_INSTALL_DIR)"; path=""; branch="" ;;
    esac
  done
  [ -n "$path" ] && printf '%s\t%s\t%s\n' "$path" "${branch:-(detached)}" "$(env_value "$path" GHIDRA_INSTALL_DIR)"
}

# Warn if >1 worktree resolves to the same non-empty GHIDRA_INSTALL_DIR.
warn_ghidra_collisions() {
  worktree_rows | awk -F'\t' '
    $3 != "" { cnt[$3]++; where[$3] = where[$3] "\n      " $1 " (" $2 ")" }
    END {
      for (g in cnt) if (cnt[g] > 1) {
        printf "warning: %d worktrees share Ghidra install:\n  %s%s\n", cnt[g], g, where[g] > "/dev/stderr"
        printf "  -> headless tests (run_disasm_test / run_fw_parity) cannot run in these in parallel;\n" > "/dev/stderr"
        printf "     the module is a singleton per install. Point one at a second Ghidra in its .c28x.env.\n" > "/dev/stderr"
      }
    }'
}

seed_env() {  # <src-root> <dst-root>
  local src="$1" dst="$2" f
  f="$dst/.c28x.env"   # NB: separate statement -- `local f="$dst/..."` expands $dst before it is assigned (set -u)
  if [ -f "$f" ]; then echo "  .c28x.env already present -- left as is"; return 0; fi
  if [ -f "$src/.c28x.env" ]; then
    cp "$src/.c28x.env" "$f"; echo "  seeded .c28x.env (copied from the main worktree)"
  elif [ -n "${GHIDRA_INSTALL_DIR:-}" ]; then
    {
      echo "# Seeded by scripts/worktree.sh from the environment. Edit for this worktree."
      echo "GHIDRA_INSTALL_DIR=${GHIDRA_INSTALL_DIR}"
      [ -n "${C2000WARE:-}" ] && echo "C2000WARE=${C2000WARE}"
      [ -n "${JAVA_HOME:-}" ] && echo "JAVA_HOME=${JAVA_HOME}"
    } > "$f"
    echo "  seeded .c28x.env from the current environment"
  elif [ -f "$src/.c28x.env.example" ]; then
    cp "$src/.c28x.env.example" "$f"; echo "  no source config + GHIDRA_INSTALL_DIR unset -- wrote a template; EDIT $f"
  else
    echo "  no config available to seed -- create $f by hand (see .c28x.env.example)"
  fi
}

cmd_add() {
  local branch="${1:-}" path="${2:-}"
  [ -n "$branch" ] || die "usage: worktree.sh add <branch> [path]"
  local root reponame sanitized base
  root=$(main_root)
  reponame=$(basename "$root")
  sanitized=${branch//\//-}
  path=${path:-"$(dirname "$root")/${reponame}-worktrees/${sanitized}"}
  [ -e "$path" ] && die "target path already exists: $path"
  mkdir -p "$(dirname "$path")"

  if git -C "$root" show-ref --verify --quiet "refs/heads/$branch"; then
    echo "checking out existing local branch '$branch' at $path"
    git -C "$root" worktree add "$path" "$branch"
  elif git -C "$root" show-ref --verify --quiet "refs/remotes/origin/$branch"; then
    echo "checking out origin/$branch (new tracking branch) at $path"
    git -C "$root" worktree add --track -b "$branch" "$path" "origin/$branch"
  else
    base=HEAD
    if   git -C "$root" show-ref --verify --quiet refs/remotes/origin/main; then base=origin/main
    elif git -C "$root" show-ref --verify --quiet refs/heads/main;          then base=main; fi
    echo "creating new branch '$branch' off $base at $path"
    git -C "$root" worktree add -b "$branch" "$path" "$base"
  fi

  seed_env "$root" "$path"
  echo
  echo "Done. Next:"
  echo "  cd \"$path\""
  echo "  scripts/worktree.sh env      # confirm this worktree's resolved config"
  echo
  warn_ghidra_collisions
}

cmd_list() {
  printf '%-52s  %-28s  %s\n' "WORKTREE" "BRANCH" "GHIDRA_INSTALL_DIR"
  worktree_rows | while IFS=$'\t' read -r p b g; do
    printf '%-52s  %-28s  %s\n' "$p" "$b" "${g:-<unset>}"
  done
  echo
  warn_ghidra_collisions
}

cmd_remove() {
  local path="${1:-}"
  [ -n "$path" ] || die "usage: worktree.sh remove <path>  (append --force if it has local changes)"
  shift
  git worktree remove "$path" "$@"
  echo "removed worktree: $path  (its branch still exists; delete with: git branch -d <branch>)"
}

cmd_env() {
  local path="${1:-$(git rev-parse --show-toplevel 2>/dev/null || die 'not inside a git repository')}"
  path=$(cd "$path" && pwd)
  echo "worktree: $path"
  if [ -f "$path/.c28x.env" ]; then echo "config:   $path/.c28x.env"; else echo "config:   (no .c28x.env -- values below are from the ambient environment)"; fi
  local k
  for k in GHIDRA_INSTALL_DIR C2000WARE JAVA_HOME; do
    printf '  %-20s %s\n' "$k" "$(env_value "$path" "$k")"
  done
}

cmd="${1:-help}"; shift || true
case "$cmd" in
  add)    cmd_add    "$@" ;;
  list)   cmd_list   "$@" ;;
  remove) cmd_remove "$@" ;;
  env)    cmd_env    "$@" ;;
  help|-h|--help)
    cat <<'EOF'
git-worktree helper for ghidra-tms320c28x. See docs/WORKTREES.md.

  add <branch> [path]     create/checkout a worktree + seed its .c28x.env
  list                    list worktrees + their pinned GHIDRA_INSTALL_DIR
  remove <path> [--force] git worktree remove <path>
  env [path]              print resolved config for a worktree (default: cwd)
  help
EOF
    ;;
  *) die "unknown command '$cmd' (try: add | list | remove | env | help)" ;;
esac
