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
# ONE DELIBERATE EXCEPTION: a specialised REPEATED form. The repeated program transfers
# (PREAD / PWRITE / XPREAD / XPWRITE in tms320c28x_rpt.sinc) model the C28x program-pointer
# shadow, which the generic wrapper cannot express, so they are top-level constructors that
# claim `rpt_phase=0` and pre-empt the wrapper. That is only safe when the constructor is a
# strict SUBSET of the wrapper's pattern, which needs the wrapper's other two context bits
# too -- so this check demands `rpt_active=1` AND `rptb_flag=0` alongside `rpt_phase=0`.
# Without them the pattern merely OVERLAPS the wrapper's and sleigh reports "constructor
# patterns cannot be distinguished" (or silently resolves the wrong way), which is the same
# class of silent failure this test exists to prevent.
#
# WHY THIS TEST EXISTS. A new `:MNEMONIC` added without `& rpt_phase=1` decodes perfectly
# and passes every existing fixture. The only symptom is that `RPT || <that instruction>`
# quietly executes once instead of N+1 times -- wrong emulation and a missing loop in the
# decompiler, with nothing failing to point at it. run_disasm_test cannot catch it: the
# listing is correct.
#
# Sub-table definitions (`name: ... is ...`) are not top-level and are exempt.
#
# SCOPE: PER LANGUAGE, NOT PER DIRECTORY. The whole problem starts with a `:^instruction`
# wrapper, so a language that has none has nothing to partition and is skipped -- the CLA
# (tms320c28x_cla.slaspec) has no repeat instruction and no rpt_phase context variable at
# all, so demanding the bit on its constructors would be demanding a field that does not
# exist. Each .slaspec's @include tree is resolved and gated on whether it contains a
# wrapper, which keeps this correct automatically when another language is added. A .sinc
# that no .slaspec includes is an error, not a silent skip.
#
# Usage:  pwsh -File tests\run_phase_check.ps1 [-Module <module-root>]
param(
  [string]$Module = (Split-Path -Parent $PSScriptRoot)
)
$ErrorActionPreference = "Stop"
$lang = Join-Path $Module "data\languages"
if (-not (Test-Path $lang)) { throw "no such directory: $lang" }

$ok = 0; $wrappers = 0; $repeated = 0
$bad = New-Object System.Collections.Generic.List[string]

# Resolve one .slaspec's transitive @include tree (the spec itself first).
function Get-SpecTree {
  param([string]$Spec, [string]$LangDir)
  $tree = [System.Collections.Generic.List[string]]::new()
  $queue = [System.Collections.Generic.Queue[string]]::new()
  $tree.Add($Spec); $queue.Enqueue($Spec)
  while ($queue.Count -gt 0) {
    foreach ($line in (Get-Content $queue.Dequeue())) {
      if ($line -notmatch '^\s*@include\s+"([^"]+)"') { continue }
      $p = Join-Path $LangDir $Matches[1]
      if ((Test-Path $p) -and -not $tree.Contains($p)) { $tree.Add($p); $queue.Enqueue($p) }
    }
  }
  return $tree
}

# NB: filter on the extension rather than `-Include`, which silently matches NOTHING
# unless the -Path ends in a wildcard -- a green run over zero files looks like a pass.
$allSinc = Get-ChildItem -Path $lang -File | Where-Object { $_.Extension -eq ".sinc" }
$specs = Get-ChildItem -Path $lang -File | Where-Object { $_.Extension -eq ".slaspec" }
if ($specs.Count -eq 0) { throw "no .slaspec found under $lang -- refusing to report a vacuous pass" }

$checkPaths = [System.Collections.Generic.List[string]]::new()
$seenPaths = [System.Collections.Generic.List[string]]::new()
foreach ($spec in $specs) {
  $tree = Get-SpecTree -Spec $spec.FullName -LangDir $lang
  foreach ($p in $tree) { if (-not $seenPaths.Contains($p)) { $seenPaths.Add($p) } }
  $hasWrapper = $false
  foreach ($p in $tree) { if (Select-String -Path $p -Pattern '^:\^' -Quiet) { $hasWrapper = $true; break } }
  if ($hasWrapper) {
    foreach ($p in $tree) { if (-not $checkPaths.Contains($p)) { $checkPaths.Add($p) } }
  } else {
    Write-Host "skipping $($spec.Name): no :^instruction wrapper, so no phase to partition"
  }
}

# Anything under data/languages that no .slaspec pulls in would escape the check entirely.
foreach ($f in $allSinc) {
  if (-not $seenPaths.Contains($f.FullName)) {
    throw "$($f.Name) is included by no .slaspec -- it would escape this check"
  }
}
if ($checkPaths.Count -eq 0) { throw "no language uses :^instruction wrappers -- refusing to report a vacuous pass" }
$files = $checkPaths | ForEach-Object { Get-Item $_ }

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
      elseif ($head -match 'rpt_phase\s*=\s*0') {
        # Specialised repeated form: legal, but only as a strict subset of the wrapper's
        # pattern, which needs the wrapper's other two context bits as well.
        if (($head -match 'rpt_active\s*=\s*1') -and ($head -match 'rptb_flag\s*=\s*0')) { $repeated++ }
        else {
          $bad.Add(("  {0}:{1}: rpt_phase=0 constructor must also carry ``rpt_active=1`` and ``rptb_flag=0```n      {2}" -f $file.Name, $start, $first))
        }
      }
      else {
        $bad.Add(("  {0}:{1}: top-level constructor missing ``& rpt_phase=1```n      {2}" -f $file.Name, $start, $first))
      }
    }
  }
}

foreach ($b in $bad) { Write-Host $b }
Write-Host ("top-level constructors with rpt_phase=1 : {0}" -f $ok)
Write-Host (":^instruction wrappers                  : {0}" -f $wrappers)
Write-Host ("specialised repeated forms              : {0}" -f $repeated)
Write-Host ("violations                              : {0}" -f $bad.Count)

if ($bad.Count -gt 0) {
  Write-Host "FAIL: phase-bit invariant violated (see above)." -ForegroundColor Red
  Write-Host "      A constructor without ``& rpt_phase=1`` cannot be wrapped by RPT/RPTB;"
  Write-Host "      ``RPT || <it>`` would execute once instead of N+1 times."
  exit 1
}
Write-Host "PASS: phase-bit invariant holds." -ForegroundColor Green
