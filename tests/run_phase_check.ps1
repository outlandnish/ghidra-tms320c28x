# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# Static invariant check for the RPT / RPTB phase-bit partition. Needs no Ghidra and no
# SLEIGH compile -- it is pure text over data/languages -- so it runs first and fails fast.
#
# THE INVARIANT. The hardware repeats are modelled by `:^instruction` prefix wrappers
# (data/languages/tms320c28x_rpt.sinc). A wrapper compiles to a variant of EVERY base
# constructor whose pattern is (wrapper_pattern AND base_pattern); if a base imposes no
# context constraint that contradicts the wrapper's, the two overlap and the resolver picks
# the base -- silently making the wrapper a no-op. The fix, as used by every shipped Ghidra
# processor with `:^instruction` (ARM, avr8, 8051, Hexagon), is a phase bit:
#
#   * every top-level `:MNEMONIC` constructor must constrain  rpt_phase=1
#   * the `:^instruction` wrappers must constrain             rpt_phase=0
#
# WHY THIS TEST EXISTS. A new `:MNEMONIC` added without `& rpt_phase=1` decodes perfectly
# and passes every existing fixture. The only symptom is that `RPT || <that instruction>`
# quietly executes once instead of N+1 times -- wrong emulation and a missing loop in the
# decompiler, with nothing failing to point at it. run_disasm_test cannot catch it: the
# listing is correct.
#
# Sub-table definitions (`name: ... is ...`) are not top-level and are exempt.
#
# Usage:  pwsh -File tests\run_phase_check.ps1 [-Module <module-root>]
param(
  [string]$Module = (Split-Path -Parent $PSScriptRoot)
)
$ErrorActionPreference = "Stop"
$lang = Join-Path $Module "data\languages"
if (-not (Test-Path $lang)) { throw "no such directory: $lang" }

$ok = 0; $wrappers = 0
$bad = New-Object System.Collections.Generic.List[string]

# NB: filter on the extension rather than `-Include`, which silently matches NOTHING
# unless the -Path ends in a wildcard -- a green run over zero files looks like a pass.
$files = Get-ChildItem -Path $lang -File | Where-Object { $_.Extension -in ".sinc", ".slaspec" }
if ($files.Count -eq 0) { throw "no .sinc/.slaspec found under $lang -- refusing to report a vacuous pass" }

foreach ($file in $files) {
  $lines = Get-Content $file.FullName
  for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -notmatch '^:') { continue }

    $first = $lines[$i]
    $start = $i + 1
    $isWrapper = $lines[$i] -match '^:\^'

    # Accumulate continuation lines until the semantic body opens. A constructor head
    # never runs more than a few lines, so bound it rather than risk running away.
    $buf = $lines[$i]
    $span = 0
    while (($buf -notmatch '\{') -and ($i + 1 -lt $lines.Count) -and ($span -lt 6)) {
      $i++; $span++
      $buf += " " + $lines[$i]
    }
    $head = if ($buf -match '\{') { $buf.Substring(0, $buf.IndexOf('{')) } else { $buf }

    if ($isWrapper) {
      $wrappers++
      if ($head -notmatch 'rpt_phase\s*=\s*0') {
        $bad.Add(("  {0}:{1}: :^instruction wrapper does not constrain rpt_phase=0`n      {2}" -f $file.Name, $start, $first))
      }
    }
    elseif ($head -match '\sis\s') {
      if ($head -match 'rpt_phase\s*=\s*1') { $ok++ }
      else {
        $bad.Add(("  {0}:{1}: top-level constructor missing ``& rpt_phase=1```n      {2}" -f $file.Name, $start, $first))
      }
    }
  }
}

foreach ($b in $bad) { Write-Host $b }
Write-Host ("top-level constructors with rpt_phase=1 : {0}" -f $ok)
Write-Host (":^instruction wrappers                  : {0}" -f $wrappers)
Write-Host ("violations                              : {0}" -f $bad.Count)

if ($bad.Count -gt 0) {
  Write-Host "FAIL: phase-bit invariant violated (see above)." -ForegroundColor Red
  Write-Host "      A constructor without ``& rpt_phase=1`` cannot be wrapped by RPT/RPTB;"
  Write-Host "      ``RPT || <it>`` would execute once instead of N+1 times."
  exit 1
}
Write-Host "PASS: phase-bit invariant holds." -ForegroundColor Green
