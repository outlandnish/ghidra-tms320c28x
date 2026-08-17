#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# Compile + install the C28x emulation state modifier (RPTB hardware-loop support).
#
# SLEIGH can't model the RPTB zero-overhead block repeat (implicit loop-back at an
# arbitrary block-end instruction). Ghidra's answer is an EmulateInstructionStateModifier
# (same mechanism Hexagon uses for its hardware loops). This compiles that class and drops
# it, plus the pspec that references it, into the installed processor module.
#
# Quick-iteration analogue of run_disasm_test.sh (which drops in the .sla). A full
# `gradle buildExtension` also compiles src/main/java into the extension jar for releases.
#
# RESTART Ghidra afterwards -- the classpath and pspec are read at startup.
#
# Env:
#   GHIDRA_INSTALL_DIR  -- required. Root of Ghidra install.
#   JAVA_HOME           -- optional. Falls back to `javac` on $PATH.

set -euo pipefail

module=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# Load this worktree's local config (.c28x.env) if present. Absent file => no-op.
. "$(dirname "${BASH_SOURCE[0]}")/_env.sh"; _c28x_load_env "$module"

: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR (or put it in .c28x.env) -- your Ghidra install root}"

# locate javac / jar
if [ -n "${JAVA_HOME:-}" ]; then
  javac="$JAVA_HOME/bin/javac"
  jartool="$JAVA_HOME/bin/jar"
else
  javac=$(command -v javac || true)
  jartool=$(command -v jar || true)
fi
[ -x "$javac" ]   || { echo "javac not found (set JAVA_HOME or put JDK on PATH)" >&2; exit 1; }
[ -x "$jartool" ] || { echo "jar not found (set JAVA_HOME or put JDK on PATH)" >&2; exit 1; }

# Compile EVERY class under src/main/java, not just the state modifier. The jar this
# produces REPLACES whatever jar the target module already has, so a partial build would
# silently drop the analyzers (FFC return, switch, ABI) that ship in the same jar.
out=$(mktemp -d -t c28x-mod-build-XXXXXX)
srclist=$(mktemp -t c28x-mod-src-XXXXXX)
trap 'rm -rf "$out" "$srclist"' EXIT
find "$module/src/main/java" -name '*.java' > "$srclist"
[ -s "$srclist" ] || { echo "no sources under $module/src/main/java" >&2; exit 1; }
# Analyzers extend Features/Base classes, so the classpath needs all of Ghidra, not just Framework.
cp=$(find "$GHIDRA_INSTALL_DIR/Ghidra" -name '*.jar' -print0 | tr '\0' ':')

# Ghidra 12.x runs on JDK 21+; --release 21 keeps the class loadable on any supported JVM.
"$javac" --release 21 -nowarn -cp "$cp" -d "$out" "@$srclist"
cls="$out/ghidra/program/emulation/TMS320C28xEmulateInstructionStateModifier.class"
[ -f "$cls" ] || { echo "compile failed (no .class)" >&2; exit 1; }

# Install into whichever single location Ghidra loads the module from (extension when
# present, else the Processors drop-in) -- the jar must land beside the .sla that
# expects it, and populating both locations makes Ghidra refuse to start.
lib=$(_c28x_install_module "$GHIDRA_INSTALL_DIR" "$module")

# REPLACE the module's existing jar rather than adding a second one. An extension already
# ships lib/ghidra-tms320c28x.jar containing these same classes; writing a differently-named
# jar beside it puts two copies of every class on the classpath and Ghidra picks by scan
# order, which is exactly the stale-class ambiguity this script exists to resolve.
existing=$(find "$lib" -maxdepth 1 -name '*.jar' -type f)
if [ "$(printf '%s\n' "$existing" | grep -c .)" = "1" ]; then
  jarpath="$existing"
else
  jarpath="$lib/TMS320C28x.jar"
fi
"$jartool" --create --file "$jarpath" -C "$out" ghidra

printf 'Installed %s (%s sources) + languages. RESTART Ghidra to load it.\n' \
  "$jarpath" "$(grep -c . "$srclist")"
