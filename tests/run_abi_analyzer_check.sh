#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# SPRU class-priority allocator regression test.
#
# The module's cspec pentries assign parameter storage in declaration order, which
# cannot express SPRU514 §7.3.1 cross-class reservation (a later `long` pre-reserves
# ACC and evicts earlier `int` args from AL/AH). TMS320C28xAbiAllocator implements
# the SPRU-priority algorithm; TMS320C28xAbiAnalyzer applies it to real functions.
#
# This harness exercises the ALLOCATOR directly (analogous to how run_abi_check.sh
# probes the cspec directly via PrototypeModel.getStorageLocations) -- it compiles
# the module's Java tree, drops the resulting JAR alongside the .sla, then runs
# DumpAbiAnalyzer.java which invokes TMS320C28xAbiAllocator.computeParamStorage
# for each probe signature.
#
# Env:
#   GHIDRA_INSTALL_DIR  -- required. Root of Ghidra install.
#   JAVA_HOME           -- optional. Falls back to `javac` on PATH.
#
# Usage:
#   tests/run_abi_analyzer_check.sh
#   tests/run_abi_analyzer_check.sh -update       # rewrite expected file
#
# NOTE: this rebuilds $mod/lib/TMS320C28x.jar with ALL analyzer + modifier
# classes bundled. Running build_modifier.sh afterwards will strip everything
# but the modifier again (its jar --create OVERWRITES). Same last-runner-wins
# pattern as .sla installs.

set -euo pipefail

module=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
. "$(dirname "${BASH_SOURCE[0]}")/_env.sh"; _c28x_load_env "$module"

: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR (or put it in .c28x.env)}"

update=0
[[ "${1:-}" == "-update" ]] && update=1

lang="$module/data/languages"
tmp=$(mktemp -d -t c28x-abianalyzer-XXXXXX)
trap 'rm -rf "$tmp"' EXIT

# 1. Compile the .sla + install alongside Module.manifest.
(cd "$lang" && "$GHIDRA_INSTALL_DIR/support/sleigh" tms320c28x.slaspec >/dev/null)
[ -f "$lang/tms320c28x.sla" ] || { echo "SLEIGH compile failed"; exit 1; }

modlib=$(_c28x_install_module "$GHIDRA_INSTALL_DIR" "$module")

# 2. Compile all src/main/java classes and package into the extension JAR.
if [ -n "${JAVA_HOME:-}" ]; then
  javac="$JAVA_HOME/bin/javac"
  jartool="$JAVA_HOME/bin/jar"
else
  javac=$(command -v javac || true)
  jartool=$(command -v jar || true)
fi
[ -x "$javac" ]   || { echo "javac not found (set JAVA_HOME or put JDK on PATH)" >&2; exit 1; }
[ -x "$jartool" ] || { echo "jar not found (set JAVA_HOME or put JDK on PATH)" >&2; exit 1; }

# Ghidra 12.x classpath = every jar under Ghidra/Framework + Ghidra/Features + Ghidra/Processors.
cp=$(find "$GHIDRA_INSTALL_DIR/Ghidra/Framework" "$GHIDRA_INSTALL_DIR/Ghidra/Features" "$GHIDRA_INSTALL_DIR/Ghidra/Processors" \
     -name '*.jar' -print0 2>/dev/null | tr '\0' ':')

classes="$tmp/classes"
mkdir -p "$classes"
mapfile -d '' srcs < <(find "$module/src/main/java" -name '*.java' -print0)
"$javac" --release 21 -cp "$cp" -d "$classes" "${srcs[@]}"
"$jartool" --create --file "$modlib/TMS320C28x.jar" -C "$classes" ghidra

# 3. Run the allocator probe.
mkdir -p "$tmp/proj" "$tmp/scripts"
cp "$module/ghidra_scripts/DumpAbiAnalyzer.java" "$tmp/scripts/DumpAbiAnalyzer.java"

raw=$("$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$tmp/proj" "abi_analyzer" \
    -import "$module/tests/fixtures/abi_probe.obj" \
    -processor "TMS320C28x:LE:32:default" \
    -scriptPath "$tmp/scripts" -postScript DumpAbiAnalyzer.java \
    -noanalysis -overwrite 2>&1) || {
    echo "$raw"; echo "analyzeHeadless failed"; exit 1;
}

got=$(printf '%s\n' "$raw" \
    | awk '/=== DUMPABIANALYZER ===/{f=1;next} /=== END ===/{f=0} f' \
    | sed 's/^[^>]*> //' \
    | sed 's/ *(GhidraScript) *$//')

expected="$module/tests/abi_analyzer.expected.txt"

if [ $update -eq 1 ]; then
    printf '%s\n' "$got" > "$expected"
    echo "wrote $expected ($(wc -l < "$expected") lines)"
    exit 0
fi

if [ ! -f "$expected" ]; then
    echo "no expected file yet; run '$0 -update' to seed it. actual output:"
    printf '%s\n' "$got"
    exit 2
fi

if diff -u "$expected" <(printf '%s\n' "$got"); then
    echo "PASS: $(wc -l < "$expected") lines match"
else
    echo "FAIL: allocator output differs from tests/abi_analyzer.expected.txt"
    exit 1
fi
