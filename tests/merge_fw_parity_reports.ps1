# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# Stitch N `run_fw_parity_bootstrap` reports into one. Same output shape as
# merge_fw_parity_reports.sh -- see that file for the format spec and rationale.
#
# Usage:
#   pwsh -File tests\merge_fw_parity_reports.ps1 [-Out merged.txt] `
#        -Reports 'label1:report1.txt','label2:report2.txt'

param(
  [Parameter(Mandatory)][string[]]$Reports,
  [string]$Out = ""
)
$ErrorActionPreference = "Stop"

$totalsKeys   = @('total','agree','wrong','undef','skew','opdiff')
$perImage     = @{}
$totalsAll    = @{}
foreach ($k in $totalsKeys) { $totalsAll[$k] = 0 }
$labels       = New-Object System.Collections.Generic.List[string]

# hist[section][key] = @{ count = int; sample = string; images = HashSet<string> }
$hist = @{ WRONG = @{}; UNDEF = @{}; SKEW = @{} }

foreach ($entry in $Reports) {
  $colon = $entry.IndexOf(':')
  if ($colon -lt 1) { throw "expected <label>:<path>, got: $entry" }
  $label = $entry.Substring(0, $colon)
  $path  = $entry.Substring($colon + 1)
  if (-not (Test-Path -LiteralPath $path)) { throw "no such report: $path" }
  if (-not $perImage.ContainsKey($label)) {
    $labels.Add($label) | Out-Null
    $perImage[$label] = @{}
    foreach ($k in $totalsKeys) { $perImage[$label][$k] = 0 }
  }

  $section = ""
  foreach ($ln in Get-Content -LiteralPath $path) {
    if ($ln -match '^SUMMARY\s') {
      foreach ($tok in ($ln -split '\s+')) {
        if ($tok -match '^(\w+)=(\d+)$') {
          $k = $Matches[1]; $v = [int]$Matches[2]
          if ($totalsAll.ContainsKey($k)) {
            $totalsAll[$k]      += $v
            $perImage[$label][$k] += $v
          }
        }
      }
      continue
    }
    if     ($ln -match '^---\s+WRONG-HIST') { $section = "WRONG"; continue }
    elseif ($ln -match '^---\s+UNDEF-HIST') { $section = "UNDEF"; continue }
    elseif ($ln -match '^---\s+SKEW-HIST')  { $section = "SKEW";  continue }
    elseif ($ln -match '^---')              { $section = "";      continue }
    if (-not $section) { continue }
    $p = $ln -split "`t"
    if ($p.Count -lt 2) { continue }
    $count = [int]$p[0]
    $key   = $p[1] -replace '^TI=', ''
    $sample = ""
    for ($i = 2; $i -lt $p.Count; $i++) {
      if ($p[$i] -match '^sample=(.+)$') { $sample = $Matches[1]; break }
    }
    if (-not $hist[$section].ContainsKey($key)) {
      $hist[$section][$key] = @{ count = 0; sample = $sample; images = New-Object System.Collections.Generic.HashSet[string] }
    }
    $hist[$section][$key].count += $count
    [void]$hist[$section][$key].images.Add($label)
  }
}

$lines = New-Object System.Collections.Generic.List[string]
$sum = "SUMMARY " + (($totalsKeys | ForEach-Object { "$($_)=$($totalsAll[$_])" }) -join ' ')
$lines.Add($sum) | Out-Null
$lines.Add("") | Out-Null
$lines.Add("--- PER-IMAGE ---") | Out-Null
foreach ($lab in ($labels | Sort-Object)) {
  $s = "  $lab " + (($totalsKeys | ForEach-Object { "$($_)=$($perImage[$lab][$_])" }) -join ' ')
  $lines.Add($s) | Out-Null
}
foreach ($sec in @('WRONG','UNDEF','SKEW')) {
  $lines.Add("") | Out-Null
  $lines.Add("--- $sec-HIST (top 30 by count) ---") | Out-Null
  $rows = $hist[$sec].GetEnumerator() | Sort-Object -Property { $_.Value.count } -Descending | Select-Object -First 30
  foreach ($e in $rows) {
    $keyDisp = if ($sec -eq "WRONG") { $e.Key } else { "TI=$($e.Key)" }
    $imgs = ($e.Value.images | Sort-Object) -join ','
    $lines.Add(("{0}`t{1}`tsample={2}`timages={3}" -f $e.Value.count, $keyDisp, $e.Value.sample, $imgs)) | Out-Null
  }
}

if ($Out) {
  Set-Content -LiteralPath $Out -Value $lines.ToArray() -Encoding ascii
  Write-Host "merged: $Out"
} else {
  $lines | ForEach-Object { Write-Host $_ }
}
