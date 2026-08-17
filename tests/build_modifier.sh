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

src="$module/src/main/java/ghidra/program/emulation/TMS320C28xEmulateInstructionStateModifier.java"
# Ghidra 12.x classpath is any jar under Ghidra/Framework.
cp=$(find "$GHIDRA_INSTALL_DIR/Ghidra/Framework" -name '*.jar' -print0 | tr '\0' ':')
out=$(mktemp -d -t c28x-mod-build-XXXXXX)
trap 'rm -rf "$out"' EXIT

# Ghidra 12.x runs on JDK 21+; --release 21 keeps the class loadable on any supported JVM.
"$javac" --release 21 -cp "$cp" -d "$out" "$src"
cls="$out/ghidra/program/emulation/TMS320C28xEmulateInstructionStateModifier.class"
[ -f "$cls" ] || { echo "compile failed (no .class)" >&2; exit 1; }

# Install into whichever single location Ghidra loads the module from (extension when
# present, else the Processors drop-in) -- the jar must land beside the .sla that
# expects it, and populating both locations makes Ghidra refuse to start.
lib=$(_c28x_install_module "$GHIDRA_INSTALL_DIR" "$module")
"$jartool" --create --file "$lib/TMS320C28x.jar" -C "$out" ghidra

printf 'Installed %s/TMS320C28x.jar + languages. RESTART Ghidra to load the state modifier.\n' "$lib"
