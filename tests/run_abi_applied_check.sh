#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# SPRU applied-signature regression test (end-to-end).
#
# Complements run_abi_check (probes the cspec via PrototypeModel directly) and
# run_abi_analyzer_check (probes the pure allocator). This harness is the only
# one that exercises Ghidra's real signature-application path:
# ApplyFunctionSignatureCmd -> Function.updateFunction -> TMS320C28xAbiAnalyzer.
# Only that path can test:
#   - varargs (setVarArgs(true) round-trips into fn.hasVarArgs(), which the
#     analyzer honors to force the last named arg to the stack per SPRU
#     §7.3.1's va_list-contiguity rule);
#   - hidden struct-return pointer (the cspec's <pentry storage="hiddenret"> is
#     only consulted by the real function-analysis path, not by
#     PrototypeModel.getStorageLocations()).
#
# The .obj fixture and Ghidra install / jar-bundling flow mirror
# run_abi_analyzer_check exactly. Auto-analysis IS enabled (unlike the two
# earlier harnesses) so functions materialize from ELF symbols before we
# apply signatures against them; the analyzer is then invoked EXPLICITLY from
# DumpAppliedProtos.java so its output doesn't race with AutoAnalysisManager.
#
# Env:
#   GHIDRA_INSTALL_DIR  -- required. Root of Ghidra install.
#   JAVA_HOME           -- optional. Falls back to `javac` on PATH.
#
# Usage:
#   tests/run_abi_applied_check.sh
#   tests/run_abi_applied_check.sh -update       # rewrite expected file
#
# NOTE: same last-runner-wins jar caveat as run_abi_analyzer_check --
# subsequent build_modifier.sh will overwrite the analyzer jar with just the
# modifier class.

set -euo pipefail

module=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
. "$(dirname "${BASH_SOURCE[0]}")/_env.sh"; _c28x_load_env "$module"

: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR (or put it in .c28x.env)}"

update=0
[[ "${1:-}" == "-update" ]] && update=1

lang="$module/data/languages"
tmp=$(mktemp -d -t c28x-abiapplied-XXXXXX)
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

cp=$(find "$GHIDRA_INSTALL_DIR/Ghidra/Framework" "$GHIDRA_INSTALL_DIR/Ghidra/Features" "$GHIDRA_INSTALL_DIR/Ghidra/Processors" \
     -name '*.jar' -print0 2>/dev/null | tr '\0' ':')

classes="$tmp/classes"
mkdir -p "$classes"
mapfile -d '' srcs < <(find "$module/src/main/java" -name '*.java' -print0)
"$javac" --release 21 -cp "$cp" -d "$classes" "${srcs[@]}"
"$jartool" --create --file "$modlib/TMS320C28x.jar" -C "$classes" ghidra

# 3. Run the applied-signature probe. Analysis IS enabled here (functions need
# to materialize from ELF symbols before we can apply signatures against them);
# a generous timeout because the FPU decompiler pass on this fixture is slow.
mkdir -p "$tmp/proj" "$tmp/scripts"
cp "$module/ghidra_scripts/DumpAppliedProtos.java" "$tmp/scripts/DumpAppliedProtos.java"

raw=$("$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$tmp/proj" "abi_applied" \
    -import "$module/tests/fixtures/abi_probe.obj" \
    -processor "TMS320C28x:LE:32:default" \
    -scriptPath "$tmp/scripts" -postScript DumpAppliedProtos.java \
    -analysisTimeoutPerFile 300 -overwrite 2>&1) || {
    echo "$raw"; echo "analyzeHeadless failed"; exit 1;
}

got=$(printf '%s\n' "$raw" \
    | awk '/=== DUMPAPPLIEDPROTOS ===/{f=1;next} /=== END ===/{f=0} f' \
    | sed 's/^[^>]*> //' \
    | sed 's/ *(GhidraScript) *$//')

expected="$module/tests/abi_applied.expected.txt"

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
    echo "FAIL: applied-signature output differs from tests/abi_applied.expected.txt"
    exit 1
fi
