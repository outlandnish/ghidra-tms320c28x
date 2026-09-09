#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# Firmware decode-parity via BOOTSTRAP: unlike run_fw_parity.sh (a fixed word range
# specified by the caller), this walks the call graph starting from data-side
# seed addresses (`_c_int00`, PIE vector table entries, or explicit `-Seed`s),
# using dis2000 as the disassembler for both region discovery AND ground truth.
#
# Why bootstrap rather than "sweep the functions Ghidra found":
#   Our own analyzer's function boundaries reflect where OUR SLEIGH decoder
#   followed flow. A wrong-length constructor truncates the function at the skew;
#   a mis-modeled branch target sends flow into data; an UNDEF opcode cuts flow
#   entirely. Those are exactly the spec gaps we most want to find, and they
#   HIDE THEMSELVES from a function-bounded sweep. So we discover code the way
#   TI's own toolchain would: linearly decode from an entry with dis2000, walk to
#   the next LRETR/LRET/IRET, extract call targets, enqueue, repeat. Bounds and
#   ground truth come from the same oracle; our decoder is only ever the
#   comparison, never the map.
#
# Pipeline:
#   1. Take seeds from -Seed args (repeatable) and/or -Seeds <file.tsv> (one word
#      address per non-comment line, first column).
#   2. For each unvisited seed, slice a MaxSpan-word window out of the swapped
#      firmware, `.word`-encode, asm2000 -> COFF -> dis2000. Walk lines top-to-
#      bottom; the region ends at the first LRETR/LRET/LRETE/IRET (or MaxSpan
#      words if no return found, which is logged and treated as a soft failure
#      for that seed's coverage rather than an abort).
#   3. Collect literal CALL targets (LCR/LC/FFC) as new seeds; branch targets
#      stay within the function's linear decode and are not enqueued. Cache TI
#      decodes region-by-region so step 5 doesn't re-invoke dis2000.
#   4. Emit regions.tsv (start_word, len_words, seed_source), then analyzeHeadless
#      DumpFwParityOurs.java once against a fresh flat import of the same firmware
#      at the same base -- one Ghidra boot for ALL regions.
#   5. Per region, align TI's mnem-lines against ours on word address. Aggregate
#      by mnemonic: WRONG (ours != TI), UNDEF (ours failed), SKEW (ours picked a
#      different instruction length so our next start-word doesn't sit where
#      TI's does).
#
# Env / prereqs:
#   GHIDRA_INSTALL_DIR  Ghidra install (matches this worktree; use .c28x.env).
#   C2000WARE           TI C2000 CGT install with bin/asm2000 + bin/dis2000.
#
# Usage:
#   tests/run_fw_parity_bootstrap.sh -Fw <swapped.bin> -Base 0x82000 -Seed 0x820e0 \
#        [-Seed 0x82f10 ...] [-Seeds seeds.tsv] [-MaxSpan 4096] [-OutDir out/]

set -euo pipefail

module=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
. "$(dirname "${BASH_SOURCE[0]}")/_env.sh"; _c28x_load_env "$module"

: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR (or .c28x.env) -- your Ghidra install root}"
: "${C2000WARE:?set C2000WARE (or .c28x.env) -- TI C2000 CGT root with bin/asm2000, bin/dis2000}"

Fw=""; Base=0x82000; MaxSpan=4096; OutDir=""
seeds=()
seeds_file=""
while [ $# -gt 0 ]; do
  case "$1" in
    -Fw)      Fw=$2;         shift 2;;
    -Base)    Base=$2;       shift 2;;
    -Seed)    seeds+=("$2"); shift 2;;
    -Seeds)   seeds_file=$2; shift 2;;
    -MaxSpan) MaxSpan=$2;    shift 2;;
    -OutDir)  OutDir=$2;     shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -n "$Fw" ] || { echo "usage: $0 -Fw <swapped.bin> -Base <wordaddr> -Seed <wordaddr> [-Seed ...]" >&2; exit 2; }
[ -f "$Fw" ] || { echo "no such firmware image: $Fw" >&2; exit 1; }

if [ -n "$seeds_file" ]; then
  while IFS= read -r line; do
    line=${line%%#*}
    line=$(printf '%s' "$line" | awk '{$1=$1; print $1}')  # trim + take first col
    [ -z "$line" ] && continue
    seeds+=("$line")
  done < "$seeds_file"
fi
[ "${#seeds[@]}" -gt 0 ] || { echo "no seeds -- give -Seed or -Seeds" >&2; exit 2; }

base=$((Base))
maxSpan=$((MaxSpan))
img_size=$(stat -c%s "$Fw" 2>/dev/null || stat -f%z "$Fw")
img_words=$((img_size / 2))
img_end=$((base + img_words))

work=$(mktemp -d -t c28x-fwbs-XXXXXX)
trap 'rm -rf "$work"' EXIT
tibin="$C2000WARE/bin"

if [ -z "$OutDir" ]; then
  OutDir="$module/tests/out/fw_bootstrap"
fi
mkdir -p "$OutDir"

# ---------- BFS with dis2000 as disassembler --------------------------------
# Records:
#   regions_tsv        : <start_word_hex>\t<len_words_dec>\t<source>
#   ti_dump_tsv        : <start_word_hex>\t<word_addr_hex>\t<mnem+ops>
#                        (+ terminating `EOR` line per region for split reads)
#   unresolved_tsv     : call sites whose target lies outside the loaded image
regions_tsv="$OutDir/regions.tsv"
ti_dump_tsv="$OutDir/ti_dump.tsv"
unresolved_tsv="$OutDir/unresolved.tsv"
: > "$regions_tsv"
: > "$ti_dump_tsv"
: > "$unresolved_tsv"

declare -A visited=()

# Return mnemonics: what ENDS a region during BFS. Anything else keeps the linear
# decode going within the region. Rationale in header (function granularity).
end_re='^(LRETR|LRET|LRETE|IRET|IRETE)$'

# Call-target mnemonics: what ENQUEUES a new seed. Branches stay in-region.
call_re='^(LCR|LC|FFC)$'

# Given a seed word address, decode from there with dis2000 for up to maxSpan
# words. Prints (to stdout) TI dump lines and (via file) the set of newly-
# discovered call targets. Returns len_words consumed (via echoed final line).
decode_from() {  # <seed_word_hex> <source_tag>
  local seed_hex="$1" src="$2"
  local seed=$((16#${seed_hex#0x}))
  local off=$(( (seed - base) * 2 ))
  if [ "$off" -lt 0 ] || [ $((off + 2)) -gt "$img_size" ]; then
    printf '%s\tOOR\t0\t%s\n' "$seed_hex" "$src" >> "$regions_tsv"
    return
  fi
  local words_to_end=$(( img_words - (seed - base) ))
  local span=$(( maxSpan < words_to_end ? maxSpan : words_to_end ))
  local bin="$work/reg_${seed_hex}.bin"
  local asm="$work/reg_${seed_hex}.asm"
  local obj="$work/reg_${seed_hex}.obj"
  dd if="$Fw" of="$bin" bs=1 skip="$off" count=$((span * 2)) status=none
  {
    printf '        .text\n'
    hexdump -v -e '1/2 "%04x\n"' "$bin" | awk '{ printf "        .word 0x%s\n", $1 }'
  } > "$asm"
  # asm2000 chatters on stdout; only its exit status matters here. If it exits
  # nonzero we treat the whole seed as unusable rather than importing a broken
  # object -- dis2000 on a truncated .obj emits nothing and we would silently
  # zero-length the region.
  if ! (cd "$work" && "$tibin/asm2000" -v28 "reg_${seed_hex}.asm" -o="reg_${seed_hex}.obj" >/dev/null 2>&1); then
    printf '%s\tASM_FAIL\t0\t%s\n' "$seed_hex" "$src" >> "$regions_tsv"
    return
  fi
  # dis2000 -i forces .text-as-code; without it dis2000 will refuse to disassemble
  # a section flagged data.
  local dis
  dis=$("$tibin/dis2000" -i "$obj" 2>&1)

  # Two passes over the output: (a) find the terminating return + build the TI
  # dump slice, (b) rescan the slice for call targets. Two passes are simpler
  # than combining and don't matter perf-wise for the small per-region output.
  local end_wrel=-1
  local dump=""
  while IFS= read -r line; do
    # dis2000 line format: `<8 hex WORD address>  <4 hex opcode word>  <MNEM>  <ops>`
    # (multi-word instructions print each follow-on word on its OWN line with no
    # mnemonic, so we don't need a repeat group for the opcode.) The `||` prefix
    # marks a repeated or parallel instruction; strip so the real mnemonic wins.
    # The 8-hex column is a word address relative to section start, NOT a byte
    # offset -- easy to get wrong; check run_fw_parity's regex against dis2000
    # output before changing this.
    if [[ "$line" =~ ^[[:space:]]*([0-9a-fA-F]{8})[[:space:]]+[0-9a-fA-F]{4}[[:space:]]+(\|\|)?[[:space:]]*([A-Z][A-Z0-9_]*)[[:space:]]*(.*)$ ]]; then
      local wrel="${BASH_REMATCH[1]}"
      local mnem="${BASH_REMATCH[3]}"
      local ops="${BASH_REMATCH[4]}"
      local wrel_dec=$((16#$wrel))
      local wa=$((seed + wrel_dec))
      # Collapse whitespace and trailing junk in ops for stable comparison.
      ops=$(printf '%s' "$ops" | awk '{$1=$1; print}')
      local text
      if [ -z "$ops" ]; then text="$mnem"; else text="$mnem $ops"; fi
      dump+=$(printf '%08x\t%08x\t%s\n' "$seed" "$wa" "$text")$'\n'
      if [[ "$mnem" =~ $end_re ]]; then
        end_wrel=$wrel_dec
      fi
    fi
    if [ "$end_wrel" -ge 0 ]; then break; fi
  done <<< "$dis"

  local len_words
  if [ "$end_wrel" -ge 0 ]; then
    # +1 word for the 1-word return itself (all four documented returns are single-word).
    len_words=$(( end_wrel + 1 ))
  else
    len_words="$span"
    printf 'no-return-hit\t%s\tspan=%d\t%s\n' "$seed_hex" "$span" "$src" >> "$unresolved_tsv"
  fi
  printf '%s\t%d\t%s\n' "$seed_hex" "$len_words" "$src" >> "$regions_tsv"
  printf '%s' "$dump" >> "$ti_dump_tsv"
  printf '%08x\tEOR\t%d\n' "$seed" "$len_words" >> "$ti_dump_tsv"

  # Extract call targets from the region we just accepted.
  printf '%s' "$dump" | awk -F'\t' -v seed_hex="$seed_hex" '
    NF < 3 { next }
    {
      n = split($3, parts, " ")
      mnem = parts[1]
      if (mnem !~ /^(LCR|LC|FFC)$/) next
      # LCR 0xNNNNNN | LC 0xNNNNNN | FFC XAR7, 0xNNNNNN
      tgt = ""
      for (i = 2; i <= n; i++) {
        if (parts[i] ~ /^0x[0-9a-fA-F]+/) { tgt = parts[i]; break }
      }
      if (tgt == "") next
      gsub(/,$/, "", tgt)
      printf "%s\n", tgt
    }
  '
}

queue=()
for s in "${seeds[@]}"; do queue+=("$s|explicit"); done

processed=0
while [ "${#queue[@]}" -gt 0 ]; do
  entry="${queue[0]}"
  queue=("${queue[@]:1}")
  seed_hex="${entry%%|*}"
  src="${entry##*|}"
  # Normalize seed_hex to `0xXXXX` lowercase for the visited key.
  seed_norm=$(printf '0x%x' $((16#${seed_hex#0x})))
  [ -n "${visited[$seed_norm]:-}" ] && continue
  visited[$seed_norm]=1
  processed=$((processed + 1))
  # Decode and collect any new call targets on stdout.
  new_targets=$(decode_from "$seed_norm" "$src")
  while IFS= read -r t; do
    [ -z "$t" ] && continue
    t_norm=$(printf '0x%x' $((16#${t#0x})))
    [ -n "${visited[$t_norm]:-}" ] && continue
    # Prune out-of-image early so the queue does not fill with nonsense pointed
    # to by mis-decoded operand words.
    t_dec=$((16#${t_norm#0x}))
    if [ "$t_dec" -lt "$base" ] || [ "$t_dec" -ge "$img_end" ]; then
      printf 'oor-call\t%s\tfrom=%s\n' "$t_norm" "$seed_norm" >> "$unresolved_tsv"
      continue
    fi
    queue+=("$t_norm|from:$seed_norm")
  done <<< "$new_targets"
done

echo "BFS: $processed seed(s) processed, $(wc -l < "$regions_tsv") region(s) recorded"

# ---------- our-side decode: ONE headless import for all regions ------------
ws="$work/run"
mkdir -p "$ws/proj" "$ws/scripts"
cp "$module/ghidra_scripts/DumpFwParityOurs.java" "$ws/scripts/"
our_dump="$OutDir/our_dump.tsv"

# BinaryLoader with -loader-block-base for the correct absolute base. Without it
# every region's start_word points outside the (address-0) block and every entry
# reports MISS_MEM. -loader-block-name gives the block a readable name in the
# listing (does not affect addressing).
#
# The base is in BYTES, so multiply by 2 for the wordsize-2 ram space.
base_word=$(printf '0x%x' "$base")
JAVA_TOOL_OPTIONS="-Dc28x.parity.regions.in=$regions_tsv -Dc28x.parity.regions.out=$our_dump" \
  "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$ws/proj" "bs_$(basename "$Fw" .bin)" \
    -import "$Fw" -processor "TMS320C28x:LE:32:default" \
    -loader BinaryLoader -loader-baseAddr "$base_word" \
    -scriptPath "$ws/scripts" -postScript DumpFwParityOurs.java -noanalysis -overwrite \
    -max-cpu 2 >/dev/null 2>&1 || true

[ -f "$our_dump" ] || { echo "our-side dump did not produce output" >&2; exit 1; }

# ---------- align + aggregate -----------------------------------------------
report_awk="$work/report.awk"
cat > "$report_awk" <<'AWK'
BEGIN { FS = "\t" }

# TI dump lines: <region_hex>\t<word_hex>\t<mnem_and_ops>
FILENAME == titxt {
  if ($2 == "EOR") next
  key = $1 "|" $2
  ti[key] = $3
  ti_region[key] = $1
  ti_word[key] = $2
  n = split($3, parts, " ")
  ti_mnem[key] = parts[1]
  next
}

# Ours: same format plus END markers.
FILENAME == ourstxt {
  if ($2 == "END" || $2 == "MISS_MEM") next
  key = $1 "|" $2
  ours[key] = $3
  n = split($3, parts, " ")
  ours_mnem[key] = parts[1]
  next
}

END {
  # Iterate TI ground truth. Each ti key is a definitive instruction start
  # according to dis2000. If we produced no mnem at that word, it is either
  # length skew (we consumed the word as an operand of a previous instr) or
  # <UNDEF>. We disambiguate by checking whether the word appears as our
  # start-word: if not, skew; if it does but reads <UNDEF>, undef.
  for (k in ti_mnem) {
    tim = ti_mnem[k]
    tit = ti[k]
    total++
    if (!(k in ours_mnem)) {
      skew++
      skew_hist[tim]++
      if (skew_ex[tim] == "") skew_ex[tim] = ti_word[k]
      continue
    }
    om = ours_mnem[k]
    if (om == "<UNDEF>") {
      undef++
      undef_hist[tim]++
      if (undef_ex[tim] == "") undef_ex[tim] = ti_word[k]
      continue
    }
    if (om != tim) {
      wrong++
      pair = tim "->" om
      wrong_hist[pair]++
      if (wrong_ex[pair] == "") wrong_ex[pair] = ti_word[k]
      continue
    }
    agree++
    # Same mnemonic: check operand text for cosmetic vs real diff.
    if (tolower(tit) != tolower(ours[k])) opdiff++
  }
  # And ours-only lines: instructions we decoded where TI did not. Rare but
  # worth reporting -- usually means our decoder consumed data as code past a
  # length skew and produced a spurious mnem-line.
  for (k in ours_mnem) if (!(k in ti_mnem) && ours_mnem[k] != "<UNDEF>") ours_only++

  printf "SUMMARY total=%d agree=%d wrong=%d undef=%d skew=%d opdiff=%d ours_only=%d\n",
    total, agree, wrong, undef, skew, opdiff, ours_only
  print "---WRONG-HIST---"
  for (p in wrong_hist) printf "%d\t%s\tsample=0x%s\n", wrong_hist[p], p, wrong_ex[p]
  print "---UNDEF-HIST---"
  for (m in undef_hist) printf "%d\tTI=%s\tsample=0x%s\n", undef_hist[m], m, undef_ex[m]
  print "---SKEW-HIST---"
  for (m in skew_hist) printf "%d\tTI=%s\tsample=0x%s\n", skew_hist[m], m, skew_ex[m]
}
AWK

report="$OutDir/report.txt"
awk -v titxt="$ti_dump_tsv" -v ourstxt="$our_dump" -f "$report_awk" \
  "$ti_dump_tsv" "$our_dump" | tee "$report" | head -1

# Sort the histograms by descending count for readability.
{
  head -1 "$report"
  for section in WRONG-HIST UNDEF-HIST SKEW-HIST; do
    printf '\n--- %s (top 30 by count) ---\n' "$section"
    awk -v s="---$section---" 'p && /^---/ { exit } p; $0==s { p=1 }' "$report" \
      | sort -rn -k1,1 | head -30
  done
} > "$OutDir/report_sorted.txt"

echo "  regions: $regions_tsv"
echo "  TI dump: $ti_dump_tsv"
echo "  our dump: $our_dump"
echo "  report: $OutDir/report_sorted.txt"
