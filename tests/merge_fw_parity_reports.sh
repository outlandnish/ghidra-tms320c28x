#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# Stitch N `run_fw_parity_bootstrap` reports into one. Each argument is
# `<label>:<path/to/report_sorted.txt>`; label appears in the per-image
# summaries so the merged report is legible when auditing several firmwares
# at once (typical: CPU1 + CPU2 of the same device, or two firmware ages).
#
# Output format mirrors the per-image report:
#   SUMMARY total=... agree=... wrong=... undef=... skew=... opdiff=...
#   --- PER-IMAGE ---
#     <label> total=... agree=... wrong=... undef=... skew=... opdiff=...
#     ...
#   --- WRONG-HIST (top 30 by count) ---
#     <count>  <ti->ours>  sample=0xNNN  images=<label>[,<label>...]
#   --- UNDEF-HIST (top 30 by count) ---
#     ...
#   --- SKEW-HIST (top 30 by count) ---
#     ...
#
# Counts are SUMMED across images; sample is the first one seen; the images
# column lists every input where that key surfaced (so a bug present on both
# cores is visible immediately). Emits to stdout by default; `-Out <path>`
# writes to file.
#
# Usage:
#   tests/merge_fw_parity_reports.sh [-Out merged.txt] label1:r1.txt label2:r2.txt

set -euo pipefail

Out=""
inputs=()
while [ $# -gt 0 ]; do
  case "$1" in
    -Out) Out=$2; shift 2;;
    -*)   echo "unknown arg: $1" >&2; exit 2;;
    *)    inputs+=("$1"); shift;;
  esac
done
[ "${#inputs[@]}" -gt 0 ] || { echo "usage: $0 [-Out merged.txt] <label>:<report.txt> [<label>:<report.txt> ...]" >&2; exit 2; }

tmp=$(mktemp -d -t c28x-merge-XXXXXX)
trap 'rm -rf "$tmp"' EXIT

# Feed each report through a per-input AWK that emits a normalized stream:
#   S <label> <k>=<v>
#   H <hist>  <label> <count> <key> <sample>
# where <hist> is WRONG|UNDEF|SKEW. The merger reads all normalized lines from
# a single stream and folds them.
: > "$tmp/stream.tsv"
for entry in "${inputs[@]}"; do
  label="${entry%%:*}"
  path="${entry#*:}"
  [ -f "$path" ] || { echo "no such report: $path" >&2; exit 1; }
  # SUMMARY lines are space-separated by design (the per-image report writes
  # `SUMMARY total=X agree=Y ...` on one line); histogram rows are tab-separated.
  # Two-pass with different FS is cleaner than trying to handle both in one.
  awk -v label="$label" '
    /^SUMMARY / {
      for (i = 2; i <= NF; i++) {
        split($i, kv, "=")
        printf "S\t%s\t%s\t%s\n", label, kv[1], kv[2]
      }
    }
  ' "$path" >> "$tmp/stream.tsv"
  awk -v label="$label" '
    BEGIN { FS = "\t" }
    /^--- WRONG-HIST / { section="WRONG"; next }
    /^--- UNDEF-HIST / { section="UNDEF"; next }
    /^--- SKEW-HIST /  { section="SKEW";  next }
    /^--- / { section=""; next }
    section != "" && NF >= 2 {
      # per-image line: "<count>\t<key>\tsample=0x<addr>"
      # UNDEF/SKEW keys are printed as "TI=<mnem>", strip the prefix for merge.
      count = $1
      key = $2
      sub(/^TI=/, "", key)
      sample = ""
      for (i = 3; i <= NF; i++) if ($i ~ /^sample=/) { sample = substr($i, 8); break }
      # The per-image report already renders sample with a `0x` prefix; keep as-is.
      printf "H\t%s\t%s\t%d\t%s\t%s\n", section, label, count, key, sample
    }
  ' "$path" >> "$tmp/stream.tsv"
done

merger=$(cat <<'AWK'
BEGIN { FS = "\t" }
$1 == "S" {
  # $2=label $3=key $4=value
  totals[$3] += $4
  perImage[$2][$3] = $4
  labelSeen[$2] = 1
  next
}
$1 == "H" {
  # $2=section $3=label $4=count $5=key $6=sample
  histCount[$2][$5] += $4
  if (!($2 SUBSEP $5 in histSample)) histSample[$2 SUBSEP $5] = $6
  if (histImages[$2 SUBSEP $5] == "") histImages[$2 SUBSEP $5] = $3
  else if (index("," histImages[$2 SUBSEP $5] ",", "," $3 ",") == 0) histImages[$2 SUBSEP $5] = histImages[$2 SUBSEP $5] "," $3
  next
}
END {
  # merged summary
  fields = "total agree wrong undef skew opdiff"
  n = split(fields, ffs, " ")
  printf "SUMMARY"
  for (i = 1; i <= n; i++) printf " %s=%d", ffs[i], (totals[ffs[i]] + 0)
  printf "\n\n"
  printf "--- PER-IMAGE ---\n"
  # deterministic order: alphabetic by label
  m = 0
  for (l in labelSeen) labels[++m] = l
  # bubble sort labels (few images -> fine)
  for (i = 1; i <= m; i++) for (j = i+1; j <= m; j++) if (labels[i] > labels[j]) { t = labels[i]; labels[i] = labels[j]; labels[j] = t }
  for (i = 1; i <= m; i++) {
    printf "  %s ", labels[i]
    for (k = 1; k <= n; k++) printf " %s=%d", ffs[k], (perImage[labels[i]][ffs[k]] + 0)
    printf "\n"
  }
  for (sec = 1; sec <= 3; sec++) {
    s = (sec == 1 ? "WRONG" : sec == 2 ? "UNDEF" : "SKEW")
    printf "\n--- %s-HIST (top 30 by count) ---\n", s
    q = 0
    for (k in histCount[s]) { keys[++q] = k; cnts[q] = histCount[s][k] }
    for (i = 1; i <= q; i++) for (j = i+1; j <= q; j++) if (cnts[i] < cnts[j]) {
      t = cnts[i]; cnts[i] = cnts[j]; cnts[j] = t
      t = keys[i]; keys[i] = keys[j]; keys[j] = t
    }
    cap = q < 30 ? q : 30
    for (i = 1; i <= cap; i++) {
      k = keys[i]
      label = (s == "WRONG") ? k : "TI=" k
      printf "%d\t%s\tsample=%s\timages=%s\n", cnts[i], label, histSample[s SUBSEP k], histImages[s SUBSEP k]
    }
    delete keys; delete cnts
  }
}
AWK
)

if [ -n "$Out" ]; then
  awk "$merger" "$tmp/stream.tsv" > "$Out"
  echo "merged: $Out"
else
  awk "$merger" "$tmp/stream.tsv"
fi
