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
seeds_project=""
seeds_program=""
while [ $# -gt 0 ]; do
  case "$1" in
    -Fw)           Fw=$2;            shift 2;;
    -Base)         Base=$2;          shift 2;;
    -Seed)         seeds+=("$2");    shift 2;;
    -Seeds)        seeds_file=$2;    shift 2;;
    -SeedsProject) seeds_project=$2; shift 2;;
    -SeedsProgram) seeds_program=$2; shift 2;;
    -MaxSpan)      MaxSpan=$2;       shift 2;;
    -OutDir)       OutDir=$2;        shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
if [ -n "$seeds_project" ] && [ -n "$seeds_program" ]; then
  analyzed_mode=1
else
  analyzed_mode=0
  [ -n "$Fw" ] || { echo "flash-only mode: -Fw <bin> is required (or use -SeedsProject + -SeedsProgram for the analyzed-program mode)." >&2; exit 2; }
  [ -f "$Fw" ] || { echo "no such firmware image: $Fw" >&2; exit 1; }
fi

base=$((Base))
maxSpan=$((MaxSpan))

work=$(mktemp -d -t c28x-fwbs-XXXXXX)
trap 'rm -rf "$work"' EXIT
tibin="$C2000WARE/bin"

if [ -z "$OutDir" ]; then
  OutDir="$module/tests/out/fw_bootstrap"
fi
mkdir -p "$OutDir"

# -SeedsProject / -SeedsProgram chain the seed extractor + image extractor into
# the sweep so callers don't have to remember to run either by hand. Requires
# a project that has been through SeedFunctions signal D (c_int00 exists),
# Materialize{Sections,CopyTable} (ramfunc bytes present at run addrs), and
# MarkComponentRegistry's PIE + registry passes (seed sources fire). Missing
# any of these produces near-empty outputs -- the throws below catch the two
# hard cases (no seeds / no image bytes).
image_bin=""
image_map=""
functions_tsv=""
if [ "$analyzed_mode" -eq 1 ]; then
  seeds_auto="$OutDir/seeds_auto.tsv"
  image_bin="$OutDir/image.bin"
  image_map="$OutDir/image_map.tsv"
  functions_tsv="$OutDir/functions.tsv"
  proj_dir=$(dirname "$seeds_project")
  proj_name=$(basename "$seeds_project" .gpr)
  ws_seeds="$work/seedxtract"
  mkdir -p "$ws_seeds/scripts"
  cp "$module/ghidra_scripts/DumpFwParitySeeds.java"     "$ws_seeds/scripts/"
  cp "$module/ghidra_scripts/DumpFwParityImage.java"     "$ws_seeds/scripts/"
  cp "$module/ghidra_scripts/DumpFwParityFunctions.java" "$ws_seeds/scripts/"
  JAVA_TOOL_OPTIONS="-Dc28x.parity.seeds.out=$seeds_auto -Dc28x.parity.image.bytes=$image_bin -Dc28x.parity.image.map=$image_map -Dc28x.parity.functions.out=$functions_tsv" \
    "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$proj_dir" "$proj_name" \
      -process "$seeds_program" -readOnly -noanalysis \
      -scriptPath "$ws_seeds/scripts" \
      -postScript DumpFwParitySeeds.java \
      -postScript DumpFwParityImage.java \
      -postScript DumpFwParityFunctions.java \
      -max-cpu 2 >/dev/null 2>&1 || true
  [ -f "$seeds_auto" ]    || { echo "seed extractor produced no output -- is $seeds_program in project $seeds_project analyzed?" >&2; exit 1; }
  [ -f "$image_bin" ]     || { echo "image extractor produced no output -- is $seeds_program in project $seeds_project analyzed?" >&2; exit 1; }
  [ -f "$functions_tsv" ] || { echo "functions extractor produced no output" >&2; exit 1; }
  seeds_file_extra="$seeds_auto"
else
  seeds_file_extra=""
fi

for sf in "$seeds_file_extra" "$seeds_file"; do
  [ -z "$sf" ] && continue
  while IFS= read -r line; do
    line=${line%%#*}
    line=$(printf '%s' "$line" | awk '{$1=$1; print $1}')  # trim + take first col
    [ -z "$line" ] && continue
    seeds+=("$line")
  done < "$sf"
done
[ "${#seeds[@]}" -gt 0 ] || { echo "no seeds -- give -Seed, -Seeds, or -SeedsProject+-SeedsProgram" >&2; exit 2; }
echo "Loaded ${#seeds[@]} seed(s)"

# ---------- image cache + word-address lookup --------------------------------
# In FLASH-ONLY mode there is one implicit block at $base containing the raw
# firmware. In ANALYZED mode we read image_map.tsv (from DumpFwParityImage) into
# parallel arrays: img_block_start / img_block_len / img_block_off. The slice
# helper walks them to find the block containing a given word address, and
# `dd`s from image.bin (or the raw firmware in flash-only mode) accordingly.
img_block_start=(); img_block_len=(); img_block_off=(); img_block_name=()
if [ "$analyzed_mode" -eq 1 ]; then
  img_source="$image_bin"
  while IFS=$'\t' read -r ws wl bo nm; do
    [ -z "$ws" ] && continue
    case "$ws" in \#*) continue;; esac
    img_block_start+=("$((ws))")
    img_block_len+=("$wl")
    img_block_off+=("$bo")
    img_block_name+=("$nm")
  done < "$image_map"
  [ "${#img_block_start[@]}" -gt 0 ] || { echo "image_map.tsv had no valid rows: $image_map" >&2; exit 1; }
  echo "Loaded image: $(stat -c%s "$img_source") bytes across ${#img_block_start[@]} initialized block(s)"
else
  img_source="$Fw"
  fw_size=$(stat -c%s "$Fw" 2>/dev/null || stat -f%z "$Fw")
  img_block_start+=("$((Base))")
  img_block_len+=("$((fw_size / 2))")
  img_block_off+=(0)
  img_block_name+=("flash")
fi

# resolve_word <wordAddr> -> sets out_off, out_avail, out_name (or returns 1).
resolve_word() {
  local wa=$1 i n=${#img_block_start[@]}
  for (( i=0; i<n; i++ )); do
    local s=${img_block_start[$i]} l=${img_block_len[$i]} o=${img_block_off[$i]}
    if [ "$wa" -ge "$s" ] && [ "$wa" -lt "$((s + l))" ]; then
      out_off=$(( o + (wa - s) * 2 ))
      out_avail=$(( s + l - wa ))
      out_name=${img_block_name[$i]}
      return 0
    fi
  done
  return 1
}

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
  if ! resolve_word "$seed"; then
    printf '%s\t0\tOOR:%s\n' "$seed_hex" "$src" >> "$regions_tsv"
    return
  fi
  local span=$(( maxSpan < out_avail ? maxSpan : out_avail ))
  local bin="$work/reg_${seed_hex}.bin"
  local asm="$work/reg_${seed_hex}.asm"
  local obj="$work/reg_${seed_hex}.obj"
  dd if="$img_source" of="$bin" bs=1 skip="$out_off" count=$((span * 2)) status=none
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
    # Any target that lives in an initialized block (flash or materialized
    # RAM) is fair game for BFS to visit; anything else is an unresolved OOR
    # (indirect target the compiler baked in, or a call into MMIO). Same
    # check we do at seed-visit time in decode_from.
    t_dec=$((16#${t_norm#0x}))
    if ! resolve_word "$t_dec"; then
      printf 'oor-call\t%s\tfrom=%s\n' "$t_norm" "$seed_norm" >> "$unresolved_tsv"
      continue
    fi
    queue+=("$t_norm|from:$seed_norm")
  done <<< "$new_targets"
done

echo "BFS: $processed seed(s) processed, $(wc -l < "$regions_tsv") region(s) recorded"

# ---------- our-side decode: ONE headless call for all regions ------------
# ANALYZED mode: -process the analyzed program so RAM-resident ramfunc bytes
# are readable at their run addresses (a fresh .bin import has zeroes there).
# FLASH-ONLY mode: -import the raw .bin at $Base with BinaryLoader.
ws="$work/run"
mkdir -p "$ws/scripts"
cp "$module/ghidra_scripts/DumpFwParityOurs.java" "$ws/scripts/"
our_dump="$OutDir/our_dump.tsv"
rm -f "$our_dump"

if [ "$analyzed_mode" -eq 1 ]; then
  JAVA_TOOL_OPTIONS="-Dc28x.parity.regions.in=$regions_tsv -Dc28x.parity.regions.out=$our_dump" \
    "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$proj_dir" "$proj_name" \
      -process "$seeds_program" -readOnly -noanalysis \
      -scriptPath "$ws/scripts" -postScript DumpFwParityOurs.java \
      -max-cpu 2 >/dev/null 2>&1 || true
else
  mkdir -p "$ws/proj"
  base_word=$(printf '0x%x' "$base")
  JAVA_TOOL_OPTIONS="-Dc28x.parity.regions.in=$regions_tsv -Dc28x.parity.regions.out=$our_dump" \
    "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$ws/proj" "bs_$(basename "$Fw" .bin)" \
      -import "$Fw" -processor "TMS320C28x:LE:32:default" \
      -loader BinaryLoader -loader-baseAddr "$base_word" \
      -scriptPath "$ws/scripts" -postScript DumpFwParityOurs.java -noanalysis -overwrite \
      -max-cpu 2 >/dev/null 2>&1 || true
fi

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
    # <DATA>: our-side detected the word lives inside a defined Data instance in
    # the analyzed program (BSS zero-fill, literal pool, data table). Not a spec
    # bug -- the analyzer classified the byte as data and refused to disassemble.
    # Excluding these keeps the summary honest; a BFS walk into BSS used to swamp
    # UNDEF with thousands of ITRAP0 hits (bytes 0x0000).
    if ((k in ours_mnem) && ours_mnem[k] == "<DATA>") { data_skip++; continue }
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
  for (k in ours_mnem) if (!(k in ti_mnem) && ours_mnem[k] != "<UNDEF>" && ours_mnem[k] != "<DATA>") ours_only++

  printf "SUMMARY total=%d agree=%d wrong=%d undef=%d skew=%d opdiff=%d ours_only=%d data_skip=%d\n",
    total, agree, wrong, undef, skew, opdiff, ours_only, data_skip
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

# ---------- reachability diff (analyzed mode only) ---------------------------
# For every region BFS visited (via regions.tsv), check whether our analyzer
# has a function at that entry. Absence = a function dis2000 reaches from
# data-side seeds that our analyzer never bound as a function -- usually an
# inbound call our decoder didn't recognize.
unrooted_tsv=""
if [ "$analyzed_mode" -eq 1 ]; then
  unrooted_tsv="$OutDir/unrooted.tsv"
  # Load our function set into an associative array; a bash 4+ hashmap lookup
  # is O(1) per region -- linear scans over $functions_tsv would be O(N*M).
  declare -A our_fns=()
  while IFS=$'\t' read -r ew lw nm; do
    [ -z "$ew" ] && continue
    case "$ew" in \#*) continue;; esac
    our_fns[$((ew))]=1
  done < "$functions_tsv"
  {
    printf '# entry_word\tsource_of_reach\n'
    while IFS=$'\t' read -r ew lw src; do
      [ -z "$ew" ] && continue
      case "$src" in OOR:*|ASM_FAIL:*) continue;; esac
      wa=$((ew))
      if [ -z "${our_fns[$wa]:-}" ]; then
        printf '0x%x\t%s\n' "$wa" "$src"
      fi
    done < "$regions_tsv"
  } > "$unrooted_tsv"
  unrooted_count=$(grep -c '^0x' "$unrooted_tsv" || true)
  {
    printf '\n--- REACHABILITY (BFS-visited entries NOT bound as functions: %d) ---\n' "$unrooted_count"
    grep '^0x' "$unrooted_tsv" | head -30 | sed 's/^/  /'
  } >> "$OutDir/report_sorted.txt"
  echo "  reachability: $unrooted_count BFS entries not bound as functions"
fi

echo "  regions: $regions_tsv"
echo "  TI dump: $ti_dump_tsv"
echo "  our dump: $our_dump"
echo "  report: $OutDir/report_sorted.txt"
[ -n "$unrooted_tsv" ] && echo "  unrooted: $unrooted_tsv"
