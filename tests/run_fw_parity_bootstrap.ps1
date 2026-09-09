# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# Firmware decode-parity via BOOTSTRAP: unlike run_fw_parity.ps1 (a fixed word range
# specified by the caller), this walks the call graph starting from data-side seed
# addresses (`_c_int00`, PIE vector table entries, or explicit -Seed args), using
# dis2000 as the disassembler for both region discovery AND ground truth.
#
# Why bootstrap rather than "sweep the functions Ghidra found":
#   Our own analyzer's function boundaries reflect where OUR SLEIGH decoder followed
#   flow. A wrong-length constructor truncates the function at the skew; a mis-modeled
#   branch target sends flow into data; an UNDEF cuts flow entirely. Those are exactly
#   the spec gaps we most want to find, and they hide themselves from a function-
#   bounded sweep. So bounds and ground truth both come from dis2000; our decoder is
#   only ever the comparison, never the map.
#
# Pipeline (see run_fw_parity_bootstrap.sh for the long-form architectural notes):
#   1. seeds from -Seed args (repeatable) and/or -Seeds <file> (one word address per
#      non-comment line, first column, `0x...` or decimal).
#   2. per seed: slice a MaxSpan-word window out of the swapped firmware -> .word
#      directives -> asm2000 -> dis2000 -i. Walk mnem-lines top-to-bottom; region
#      ends at the first LRETR/LRET/LRETE/IRET (or MaxSpan words on runaway).
#   3. extract literal call targets (LCR/LC/FFC) as new seeds; branch targets stay
#      within the region's linear decode. Cache TI decodes as we go so aggregation
#      does not re-run dis2000.
#   4. emit regions.tsv, then ONE headless run of DumpFwParityOurs.java against a
#      flat import of the same firmware at the same base -- ~10s startup amortized
#      across every region, not per-region.
#   5. align TI vs ours on word address; aggregate by mnemonic (WRONG/UNDEF/SKEW).
#
# Prereqs:
#   -Ghidra    Ghidra install (matches this worktree; use .c28x.env).
#   -Ti        TI C2000 CGT install with bin\asm2000.exe + bin\dis2000.exe.
#
# Usage:
#   pwsh -File tests\run_fw_parity_bootstrap.ps1 -Fw <swapped.bin> -Base 0x82000 `
#        -Seed 0x820e0 [-Seed 0x82f10 ...] [-Seeds seeds.tsv] [-MaxSpan 4096] [-OutDir out\]

param(
  [Parameter(Mandatory)][string]$Fw,
  [int]$Base       = 0x82000,
  [string[]]$Seed  = @(),
  [string]$Seeds   = "",
  [int]$MaxSpan    = 4096,
  [string]$OutDir  = "",
  [string]$Ghidra  = $env:GHIDRA_INSTALL_DIR,
  [string]$Ti      = $env:C2000WARE,
  [string]$Module  = (Split-Path -Parent $PSScriptRoot),
  [string]$Work    = $null
)

. "$PSScriptRoot\_env.ps1"
Import-C28xEnv $Module
if (-not $PSBoundParameters.ContainsKey('Ghidra')) { $Ghidra = $env:GHIDRA_INSTALL_DIR }
if (-not $PSBoundParameters.ContainsKey('Ti'))     { $Ti     = $env:C2000WARE }
if (-not $Work) { $Work = Get-C28xScratchRoot -Module $Module -Kind "fwbs" }
if (-not $Ti)     { throw "Point -Ti (or `$env:C2000WARE / .c28x.env) at the TI CGT install (with bin\asm2000.exe, bin\dis2000.exe)." }
if (-not $Ghidra) { throw "Point -Ghidra (or `$env:GHIDRA_INSTALL_DIR / .c28x.env) at your Ghidra install." }
if (-not (Test-Path $Fw)) { throw "no such firmware image: $Fw" }
$ErrorActionPreference = "Stop"
$TiBin = "$Ti\bin"
if (-not $OutDir) { $OutDir = Join-Path $Module "tests\out\fw_bootstrap" }
New-Item -ItemType Directory -Force $Work,$OutDir | Out-Null

# ---------- seeds ------------------------------------------------------------
$seedList = New-Object System.Collections.Generic.List[object]
function Parse-HexAddr([string]$s) {
  $t = $s.Trim()
  if ($t -match '^0[xX]([0-9a-fA-F]+)$') { return [Convert]::ToInt32($Matches[1], 16) }
  if ($t -match '^([0-9a-fA-F]+)$')      { return [Convert]::ToInt32($t, 16) }
  return [int]$t
}
foreach ($s in $Seed) {
  $seedList.Add(@{ addr = (Parse-HexAddr $s); src = "explicit" })
}
if ($Seeds) {
  foreach ($ln in Get-Content $Seeds) {
    $t = ($ln -split '#',2)[0].Trim()
    if (-not $t) { continue }
    $col1 = ($t -split '\s+')[0]
    $seedList.Add(@{ addr = (Parse-HexAddr $col1); src = "file" })
  }
}
if ($seedList.Count -eq 0) { throw "no seeds -- give -Seed or -Seeds" }

# ---------- image cache ------------------------------------------------------
$img = [IO.File]::ReadAllBytes($Fw)
$imgWords = [int]($img.Length / 2)
$imgEnd = $Base + $imgWords

# Return mnemonics: what ENDS a region during BFS. Everything else keeps the
# linear decode going. All four documented forms are single-word.
$endMnems = @{ 'LRETR'=$true; 'LRET'=$true; 'LRETE'=$true; 'IRET'=$true; 'IRETE'=$true }
$callMnems = @{ 'LCR'=$true; 'LC'=$true; 'FFC'=$true }

# Files we build up as BFS runs.
$regionsTsv    = Join-Path $OutDir "regions.tsv"
$tiDumpTsv     = Join-Path $OutDir "ti_dump.tsv"
$unresolvedTsv = Join-Path $OutDir "unresolved.tsv"
Set-Content -LiteralPath $regionsTsv    -Value $null -Encoding ascii
Set-Content -LiteralPath $tiDumpTsv     -Value $null -Encoding ascii
Set-Content -LiteralPath $unresolvedTsv -Value $null -Encoding ascii

$visited = @{}
$queue = New-Object System.Collections.Queue
foreach ($s in $seedList) { $queue.Enqueue($s) | Out-Null }

# We reuse a single .asm/.obj filename per invocation to avoid piling up thousands
# of temp files -- asm2000 recreates .obj each call.
$regAsm = Join-Path $Work "region.asm"
$regObj = Join-Path $Work "region.obj"

# ---------- BFS --------------------------------------------------------------
function Decode-Region([int]$seed, [string]$src) {
  # slice bytes
  $off = ($seed - $Base) * 2
  if ($off -lt 0 -or ($off + 2) -gt $img.Length) {
    Add-Content -LiteralPath $regionsTsv -Value ("0x{0:x}`t0`tOOR:{1}" -f $seed, $src)
    return @()
  }
  $wordsToEnd = $imgWords - ($seed - $Base)
  $span = [Math]::Min($MaxSpan, $wordsToEnd)
  $bytes = New-Object byte[] ($span * 2)
  [Array]::Copy($img, $off, $bytes, 0, $span * 2)

  # .word directives from raw slice bytes
  $sb = [Text.StringBuilder]::new(); [void]$sb.AppendLine("        .text")
  for ($i = 0; $i -lt $span; $i++) {
    $w = [int]$bytes[$i*2] + [int]$bytes[$i*2+1]*256
    [void]$sb.AppendLine(("        .word 0x{0:x4}" -f $w))
  }
  [IO.File]::WriteAllText($regAsm, $sb.ToString())

  # asm2000 -> obj -> dis2000
  Push-Location $Work
  & "$TiBin\asm2000.exe" -v28 (Split-Path -Leaf $regAsm) -o=(Split-Path -Leaf $regObj) 2>&1 | Out-Null
  $rc = $LASTEXITCODE
  if ($rc -ne 0 -or -not (Test-Path $regObj)) {
    Pop-Location
    Add-Content -LiteralPath $regionsTsv -Value ("0x{0:x}`t0`tASM_FAIL:{1}" -f $seed, $src)
    return @()
  }
  $dis = & "$TiBin\dis2000.exe" -i (Split-Path -Leaf $regObj) 2>&1
  Pop-Location

  # parse: dis2000 line is `<8 hex WORD address>  <4 hex opcode word>  <MNEM>  <ops>`.
  # Multi-word instructions put follow-on words on their OWN line WITHOUT a mnem,
  # so those lines fail the regex and we skip them naturally. `||` prefix marks
  # repeated or parallel instructions; strip it so the real mnem wins.
  $endWrel = -1
  $lines = New-Object System.Collections.Generic.List[string]
  $targets = New-Object System.Collections.Generic.List[int]
  foreach ($ln in $dis) {
    if ($ln -match '^\s*([0-9a-fA-F]{8})\s+[0-9a-fA-F]{4}\s+(\|\|)?\s*([A-Z][A-Z0-9_]*)\s*(.*)$') {
      $wrel = [Convert]::ToInt32($Matches[1], 16)
      $mnem = $Matches[3].ToUpper()
      $ops  = ($Matches[4].TrimEnd() -replace '\s+',' ')
      $wa   = $seed + $wrel
      $text = if ($ops) { "$mnem $ops" } else { $mnem }
      $lines.Add(("{0:x8}`t{1:x8}`t{2}" -f $seed, $wa, $text)) | Out-Null
      # call target extraction: LCR|LC|FFC with a literal 0x... operand.
      if ($callMnems.Contains($mnem)) {
        foreach ($tok in ($ops -split '[\s,]+')) {
          if ($tok -match '^0[xX]([0-9a-fA-F]+)') {
            $t = [Convert]::ToInt32($Matches[1], 16)
            if ($t -ge $Base -and $t -lt $imgEnd) { $targets.Add($t) } else {
              Add-Content -LiteralPath $unresolvedTsv -Value ("oor-call`t0x{0:x}`tfrom=0x{1:x}" -f $t, $wa)
            }
            break
          }
        }
      }
      if ($endMnems.Contains($mnem)) { $endWrel = $wrel; break }
    }
  }
  $lenWords = if ($endWrel -ge 0) { $endWrel + 1 } else {
    Add-Content -LiteralPath $unresolvedTsv -Value ("no-return-hit`t0x{0:x}`tspan={1}`t{2}" -f $seed, $span, $src)
    $span
  }
  Add-Content -LiteralPath $regionsTsv -Value ("0x{0:x}`t{1}`t{2}" -f $seed, $lenWords, $src)
  if ($lines.Count -gt 0) { Add-Content -LiteralPath $tiDumpTsv -Value $lines.ToArray() }
  Add-Content -LiteralPath $tiDumpTsv -Value ("{0:x8}`tEOR`t{1}" -f $seed, $lenWords)
  return $targets.ToArray()
}

$processed = 0
while ($queue.Count -gt 0) {
  $entry = $queue.Dequeue()
  $addr  = $entry.addr
  $src   = $entry.src
  if ($visited.Contains($addr)) { continue }
  $visited[$addr] = $true
  $processed++
  $newTargets = Decode-Region -seed $addr -src $src
  foreach ($t in $newTargets) {
    if ($visited.Contains($t)) { continue }
    $queue.Enqueue(@{ addr = $t; src = ("from:0x{0:x}" -f $addr) }) | Out-Null
  }
}
Write-Host ("BFS: {0} seed(s) processed, {1} region(s) recorded" -f $processed, ((Get-Content $regionsTsv).Count))

# ---------- our-side decode: ONE headless import for all regions ------------
$ws = Join-Path $Work "run"
Remove-Item -Recurse -Force $ws -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force "$ws\proj","$ws\scripts" | Out-Null
Copy-Item "$Module\ghidra_scripts\DumpFwParityOurs.java" "$ws\scripts\" -Force
$ourDump = Join-Path $OutDir "our_dump.tsv"

# BinaryLoader with -loader-baseAddr for the correct absolute base. This flag is
# in WORDS (matches every other address in the wordsize=2 space; see
# docs/C28X_IMAGE_SETUP.md and docs/ANALYSIS-MIGRATION.md). Without it every
# region's start_word points outside the (address-0) block and the sweep
# degrades to all MISS_MEM.
$baseWord = "0x{0:x}" -f $Base
$savedJTO = $env:JAVA_TOOL_OPTIONS
$env:JAVA_TOOL_OPTIONS = "-Dc28x.parity.regions.in=$regionsTsv -Dc28x.parity.regions.out=$ourDump"
Push-Location $ws
# JDK 25 emits sun.misc.Unsafe deprecation warnings on stderr; loosen error action
# so a single warning does not abort the whole run under `Stop`.
$prevEA = $ErrorActionPreference; $ErrorActionPreference = "Continue"
try {
  & "$Ghidra\support\analyzeHeadless.bat" "$ws\proj" ("bs_" + (Split-Path -Leaf $Fw)) `
    -import $Fw -processor "TMS320C28x:LE:32:default" `
    -loader BinaryLoader -loader-baseAddr $baseWord `
    -scriptPath "$ws\scripts" -postScript DumpFwParityOurs.java -noanalysis -overwrite `
    -max-cpu 2 2>&1 | Out-Null
} finally {
  $ErrorActionPreference = $prevEA
  Pop-Location
  $env:JAVA_TOOL_OPTIONS = $savedJTO
}
if (-not (Test-Path $ourDump)) { throw "our-side dump did not produce output" }

# ---------- align + aggregate -----------------------------------------------
# NB: DO NOT use $ti as a hashtable name here. The script param `[string]$Ti`
# lives in the same scope and PowerShell variable names are case-INSENSITIVE, so
# `$ti = @{}` gets coerced back to the string "System.Collections.Hashtable" via
# the typed-param wrapper -- every later index into it then throws "Unable to
# index into an object of type System.String" from a line that looks fine.
$tiTxt   = @{}
$tiMnem  = @{}
$ourTxt  = @{}
$ourMnem = @{}
foreach ($ln in @(Get-Content -LiteralPath $tiDumpTsv)) {
  $p = ([string]$ln) -split "`t", 3
  if ($p.Count -lt 3 -or $p[1] -eq "EOR") { continue }
  $key = "{0}|{1}" -f $p[0], $p[1]
  if ($tiTxt.Contains($key)) { continue }
  $tiTxt[$key]  = $p[2]
  $tiMnem[$key] = ($p[2] -split '\s+')[0].ToUpper()
}
foreach ($ln in @(Get-Content -LiteralPath $ourDump)) {
  $p = ([string]$ln) -split "`t", 3
  if ($p.Count -lt 3) { continue }
  if ($p[1] -eq "END" -or $p[1] -eq "MISS_MEM") { continue }
  $key = "{0}|{1}" -f $p[0], $p[1]
  $ourTxt[$key]  = $p[2]
  $ourMnem[$key] = ($p[2] -split '\s+')[0].ToUpper()
}

$total = 0; $agree = 0; $wrong = 0; $undef = 0; $skew = 0; $opdiff = 0
$wrongHist = @{}; $undefHist = @{}; $skewHist = @{}
$wrongEx = @{}; $undefEx = @{}; $skewEx = @{}
foreach ($k in @($tiMnem.Keys)) {
  $total++
  $tim = $tiMnem[$k]; $tit = $tiTxt[$k]
  $word = ($k -split '\|')[1]
  if (-not $ourMnem.Contains($k)) {
    $skew++; $skewHist[$tim] = 1 + ($skewHist[$tim] -as [int])
    if (-not $skewEx.Contains($tim)) { $skewEx[$tim] = $word }
    continue
  }
  $om = $ourMnem[$k]
  if ($om -eq "<UNDEF>") {
    $undef++; $undefHist[$tim] = 1 + ($undefHist[$tim] -as [int])
    if (-not $undefEx.Contains($tim)) { $undefEx[$tim] = $word }
    continue
  }
  if ($om -ne $tim) {
    $wrong++
    $pair = "$tim->$om"
    $wrongHist[$pair] = 1 + ($wrongHist[$pair] -as [int])
    if (-not $wrongEx.Contains($pair)) { $wrongEx[$pair] = $word }
    continue
  }
  $agree++
  if ($tit.ToLower() -ne $ourTxt[$k].ToLower()) { $opdiff++ }
}

$summary = "SUMMARY total=$total agree=$agree wrong=$wrong undef=$undef skew=$skew opdiff=$opdiff"
Write-Host $summary -ForegroundColor Cyan

$report = Join-Path $OutDir "report_sorted.txt"
$rl = New-Object System.Collections.Generic.List[string]
$rl.Add($summary) | Out-Null
$rl.Add("") | Out-Null; $rl.Add("--- WRONG-HIST (top 30 by count) ---") | Out-Null
foreach ($e in ($wrongHist.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 30)) {
  $rl.Add(("{0}`t{1}`tsample=0x{2}" -f $e.Value, $e.Key, $wrongEx[$e.Key])) | Out-Null
}
$rl.Add("") | Out-Null; $rl.Add("--- UNDEF-HIST (top 30 by count) ---") | Out-Null
foreach ($e in ($undefHist.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 30)) {
  $rl.Add(("{0}`tTI={1}`tsample=0x{2}" -f $e.Value, $e.Key, $undefEx[$e.Key])) | Out-Null
}
$rl.Add("") | Out-Null; $rl.Add("--- SKEW-HIST (top 30 by count) ---") | Out-Null
foreach ($e in ($skewHist.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 30)) {
  $rl.Add(("{0}`tTI={1}`tsample=0x{2}" -f $e.Value, $e.Key, $skewEx[$e.Key])) | Out-Null
}
Set-Content -LiteralPath $report -Value $rl.ToArray() -Encoding ascii

Write-Host ("  regions:  {0}" -f $regionsTsv)
Write-Host ("  TI dump:  {0}" -f $tiDumpTsv)
Write-Host ("  our dump: {0}" -f $ourDump)
Write-Host ("  report:   {0}" -f $report)
