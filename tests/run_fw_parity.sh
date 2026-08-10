#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# Firmware decode-parity: dis2000 (TI ground truth) vs our SLEIGH .sla, over a WORD
# range of a byte-swapped C28x firmware image. Checks REAL firmware functions
# (e.g. the AES / immobilizer routines the emulation-fidelity work targets).
#
# How it works:
#   1. slice [Start, Start+Count) words out of the swapped image (byte off = (w-Base)*2),
#   2. emit them as `.word` directives, assemble with asm2000 -> a COFF2 object,
#   3. dis2000 -i (data_as_text) that object => TI ground-truth listing,
#   4. headless-disassemble the same raw words with our installed .sla (DumpParity.java),
#   5. align on word address; report WRONG mnemonics / UNDEF / length-skew, plus a
#      side-by-side listing so operand-level (semantic) gaps can be eyeballed.
#
# A WRONG mnemonic or length-skew is a decode bug. Operand-text diffs are mostly
# cosmetic (hex vs dec, Ghidra's '@' register-direct marker, relative vs absolute
# branch targets); the ones that matter are unresolved placeholders like `mem32` /
# `*loc16`, which flag a decode-only constructor whose p-code is empty -- fatal
# for emulation, invisible to the decompiler.
#
# Env:
#   GHIDRA_INSTALL_DIR  -- required. Root of Ghidra install.
#   C2000WARE           -- required. Root of TI C2000 CGT install (contains bin/asm2000, bin/dis2000).
#
# Usage:
#   tests/run_fw_parity.sh -Fw <swapped.bin> -Start 0x9af9e -Count 0xf2 [-Base 0x82000] [-Tag aes]

set -euo pipefail

: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR to your Ghidra install root}"
: "${C2000WARE:?set C2000WARE to your TI C2000 CGT install root (contains bin/asm2000, bin/dis2000)}"

Fw=""; Start=""; Count=""; Base=0x82000; Tag="fn"
while [ $# -gt 0 ]; do
  case "$1" in
    -Fw)    Fw=$2;    shift 2;;
    -Start) Start=$2; shift 2;;
    -Count) Count=$2; shift 2;;
    -Base)  Base=$2;  shift 2;;
    -Tag)   Tag=$2;   shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -n "$Fw" ] && [ -n "$Start" ] && [ -n "$Count" ] || {
  echo "usage: $0 -Fw <swapped.bin> -Start <wordaddr> -Count <words> [-Base 0x82000] [-Tag fn]" >&2
  exit 2
}
[ -f "$Fw" ] || { echo "no such firmware image: $Fw" >&2; exit 1; }

start=$((Start))
count=$((Count))
base=$((Base))

module=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d -t c28x-fwparity-XXXXXX)
trap 'rm -rf "$work"' EXIT
tibin="$C2000WARE/bin"

img_size=$(stat -c%s "$Fw" 2>/dev/null || stat -f%z "$Fw")
off=$(( (start - base) * 2 ))
if [ "$off" -lt 0 ] || [ $((off + count*2)) -gt "$img_size" ]; then
  printf 'range [0x%x,+%d) is outside the image (size %d)\n' "$start" "$count" "$img_size" >&2
  exit 1
fi

# --- 1/2. slice words -> .word asm -> asm2000 obj ----------------------------
bin="$work/$Tag.bin"
asm="$work/$Tag.asm"
dd if="$Fw" of="$bin" bs=1 skip="$off" count=$((count*2)) status=none

{
  printf '        .text\n'
  # Little-endian: word = low_byte + (high_byte<<8). Build via hexdump.
  hexdump -v -e '1/2 "%04x\n"' "$bin" | awk '{ printf "        .word 0x%s\n", $1 }'
} > "$asm"

(cd "$work" && "$tibin/asm2000" -v28 "$Tag.asm" -o="$Tag.obj" >/dev/null 2>&1)

# --- 3. TI ground truth: dis2000 -i (force .text-as-code) --------------------
dis=$("$tibin/dis2000" -i "$work/$Tag.obj" 2>&1)

# Parse "<8hex>  <4hex>  MNEM  ops" lines. Store in two files keyed by word addr:
#   ti_txt: "wordaddr\tMNEM ops"
#   ti_mnem: "wordaddr\tMNEM"
ti_txt="$work/ti_txt.tsv"
ti_mnem="$work/ti_mnem.tsv"
: > "$ti_txt"; : > "$ti_mnem"
printf '%s\n' "$dis" | awk -v start="$start" '
  match($0, /^[[:space:]]*([0-9a-fA-F]{8})[[:space:]]+[0-9a-fA-F]{4}[[:space:]]+([A-Z][A-Z0-9_]*)[[:space:]]*(.*)$/, m) {
    wa = strtonum("0x" m[1]) + start
    mn = m[2]
    ops = m[3]
    gsub(/[[:space:]]+$/, "", ops)
    gsub(/[[:space:]]+/, " ", ops)
    line = (ops == "") ? mn : (mn " " ops)
    printf "%d\t%s\n", wa, line  > "'"$ti_txt"'"
    printf "%d\t%s\n", wa, mn    > "'"$ti_mnem"'"
  }
'

# --- 4. our SLEIGH via headless ----------------------------------------------
ws="$work/run"
mkdir -p "$ws/proj" "$ws/scripts"
cp "$module/ghidra_scripts/DumpParity.java" "$ws/scripts/"
out_txt="$work/$Tag.ours.txt"
# This Ghidra rejects `-D...` on the analyzeHeadless CLI; pass the system
# property via the JVM env instead (DumpParity reads -Dc28x.parity.out).
JAVA_TOOL_OPTIONS="-Dc28x.parity.out=$out_txt" \
  "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$ws/proj" "t_$Tag" \
    -import "$bin" -processor "TMS320C28x:LE:32:default" \
    -scriptPath "$ws/scripts" -postScript DumpParity.java -noanalysis -overwrite \
    -max-cpu 2 >/dev/null 2>&1
[ -f "$out_txt" ] || { echo "headless dump produced no output" >&2; exit 1; }

our_txt="$work/our_txt.tsv"
our_mnem="$work/our_mnem.tsv"
: > "$our_txt"; : > "$our_mnem"
awk -F'\t' -v start="$start" '
  NF>=2 {
    wa = strtonum("0x" $1) + start
    t  = $2
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", t)
    gsub(/[[:space:]]+/, " ", t)
    n = split(t, parts, " ")
    printf "%d\t%s\n", wa, t         > "'"$our_txt"'"
    printf "%d\t%s\n", wa, toupper(parts[1]) > "'"$our_mnem"'"
  }
' "$out_txt"

# --- 5. align + report -------------------------------------------------------
report="$work/report.awk"
cat > "$report" <<'AWK'
BEGIN { FS="\t" }
FILENAME == titxt   { ti_txt[$1]  = $2; next }
FILENAME == timnem  { ti_mnem[$1] = $2; next }
FILENAME == ourtxt  { our_txt[$1] = $2; next }
FILENAME == ourmnem { our_mnem[$1] = $2; next }
END {
  n=0; for (w in ti_mnem) keys[n++] = w+0
  asort(keys)
  agree=0; wrong=0; undef=0; skew=0
  wrong_out=""; undef_out=""; skew_out=""
  sbs=""
  opdiff=0
  for (i=1; i<=n; i++) {
    w = keys[i]
    tim = ti_mnem[w]; tit = ti_txt[w]
    if (!(w in our_mnem)) {
      skew++
      skew_out = skew_out sprintf("    0x%x  TI=[%s]\n", w, tit)
      sbs      = sbs      sprintf("%x  TI: %-32s | OURS: (skew) <<<SKEW\n", w, tit)
      continue
    }
    om = our_mnem[w]; ot = our_txt[w]
    if (om == "<UNDEF>") {
      undef++
      undef_out = undef_out sprintf("    0x%x  TI=[%s]\n", w, tit)
    } else if (om == tim) {
      agree++
      titn = toupper(tit); otn = toupper(ot)
      gsub(/[ ,]/, "", titn); gsub(/[ ,]/, "", otn)
      if (titn != otn) opdiff++
    } else {
      wrong++
      wrong_out = wrong_out sprintf("    0x%x  TI=[%s]  ours=[%s]\n", w, tit, ot)
    }
    mk = ""
    if (om == "<UNDEF>") mk = " <<<UNDEF"
    else if (om != tim) mk = " <<<MNEM"
    else {
      titn = toupper(tit); otn = toupper(ot)
      gsub(/[ ,]/, "", titn); gsub(/[ ,]/, "", otn)
      if (titn != otn) mk = " <<<OPS"
    }
    sbs = sbs sprintf("%x  TI: %-32s | OURS: %s%s\n", w, tit, ot, mk)
  }
  printf "TIcount %d\n", n
  printf "agree %d\n", agree
  printf "wrong %d\n", wrong
  printf "undef %d\n", undef
  printf "skew %d\n",  skew
  printf "opdiff %d\n", opdiff
  printf "---WRONG---\n%s", wrong_out
  printf "---UNDEF---\n%s", undef_out
  printf "---SKEW---\n%s",  skew_out
  printf "---SBS---\n%s",   sbs
}
AWK

r=$(awk -v titxt="$ti_txt" -v timnem="$ti_mnem" -v ourtxt="$our_txt" -v ourmnem="$our_mnem" \
       -f "$report" "$ti_txt" "$ti_mnem" "$our_txt" "$our_mnem")

get() { printf '%s\n' "$r" | awk -v k="$1" '$1==k { print $2; exit }'; }
section() { printf '%s\n' "$r" | awk -v k="---$1---" 'p && /^---/ { exit } p; $0==k { p=1 }'; }

ti_count=$(get TIcount)
agree=$(get agree)
wrong=$(get wrong)
undef=$(get undef)
skew=$(get skew)
opdiff=$(get opdiff)

end_word=$((start + count - 1))
printf '=== FW PARITY %s @0x%x..0x%x (%d words) ===\n' \
  "$Tag" "$start" "$end_word" "$count"
printf '  TI mnem-lines: %d   agree: %d   WRONG-mnem: %d   UNDEF: %d   skew: %d\n' \
  "$ti_count" "$agree" "$wrong" "$undef" "$skew"

if [ "$wrong" -gt 0 ]; then
  printf '\n  --- WRONG MNEMONICS (decode bug) ---\n'
  section WRONG
fi
if [ "$undef" -gt 0 ]; then
  printf '\n  --- UNDEF (ours failed to decode) ---\n'
  section UNDEF
fi
if [ "$skew" -gt 0 ]; then
  printf '\n  --- LENGTH SKEW (instr-length disagreement) ---\n'
  section SKEW
fi

printf '\n  operand-text diffs (same mnemonic): %d  (mostly cosmetic; grep the side-by-side for mem32/*loc16)\n' \
  "$opdiff"

sbs="$module/tests/$Tag.sidebyside.txt"   # gitignored via tests/*.sidebyside.txt
section SBS > "$sbs"
printf '  side-by-side: %s\n' "$sbs"

# Non-zero exit if we found a real decode bug.
[ "$wrong" -eq 0 ] && [ "$skew" -eq 0 ] || exit 1
