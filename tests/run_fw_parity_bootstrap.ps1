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
  # Two modes:
  #   FLASH-ONLY: -Fw <bin> -Base <addr> (-Seed | -Seeds). Byte source is the
  #     raw firmware image; our-side dump runs on a fresh flat import. BFS can
  #     only reach code that lives in flash -- ramfunc call targets in RAM run
  #     addresses look out-of-range and are dropped as OOR.
  #   ANALYZED-PROGRAM: -SeedsProject + -SeedsProgram (against a program that
  #     has been through SeedFunctions + Materialize{Sections,CopyTable} +
  #     MarkComponentRegistry). The seed extractor runs, DumpFwParityImage
  #     dumps ALL initialized blocks (flash + materialized RAM) as one image,
  #     and BFS + our-side both walk that unified image. This is the mode that
  #     covers ramfuncs, since ramfunc bytes only exist in the analyzed program.
  # -Fw stays valid in analyzed-program mode; if given it is ignored in favor
  # of the extracted image.
  [string]$Fw           = "",
  [int]$Base            = 0x82000,
  [string[]]$Seed       = @(),
  [string]$Seeds        = "",
  [string]$SeedsProject = "",
  [string]$SeedsProgram = "",
  [int]$MaxSpan         = 4096,
  # BFS is level-based; with -Parallel N > 1 each level's regions are decoded
  # by up to N runspaces concurrently. Requires PowerShell 7+ (ForEach-Object
  # -Parallel); silently falls back to serial when running under Windows PS 5.1.
  [int]$Parallel        = 1,
  [string]$OutDir       = "",
  [string]$Ghidra       = $env:GHIDRA_INSTALL_DIR,
  [string]$Ti           = $env:C2000WARE,
  [string]$Module       = (Split-Path -Parent $PSScriptRoot),
  [string]$Work         = $null
)

. "$PSScriptRoot\_env.ps1"
Import-C28xEnv $Module
if (-not $PSBoundParameters.ContainsKey('Ghidra')) { $Ghidra = $env:GHIDRA_INSTALL_DIR }
if (-not $PSBoundParameters.ContainsKey('Ti'))     { $Ti     = $env:C2000WARE }
if (-not $Work) { $Work = Get-C28xScratchRoot -Module $Module -Kind "fwbs" }
if (-not $Ti)     { throw "Point -Ti (or `$env:C2000WARE / .c28x.env) at the TI CGT install (with bin\asm2000.exe, bin\dis2000.exe)." }
if (-not $Ghidra) { throw "Point -Ghidra (or `$env:GHIDRA_INSTALL_DIR / .c28x.env) at your Ghidra install." }
$AnalyzedMode = ($SeedsProject -and $SeedsProgram)
if (-not $AnalyzedMode) {
  if (-not $Fw) { throw "flash-only mode: -Fw <bin> is required (or use -SeedsProject + -SeedsProgram for the analyzed-program mode)." }
  if (-not (Test-Path $Fw)) { throw "no such firmware image: $Fw" }
}
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
function Load-SeedsFile([string]$path, [string]$src) {
  foreach ($ln in Get-Content $path) {
    $t = ($ln -split '#',2)[0].Trim()
    if (-not $t) { continue }
    $col1 = ($t -split '\s+')[0]
    $seedList.Add(@{ addr = (Parse-HexAddr $col1); src = $src }) | Out-Null
  }
}

# -SeedsProject / -SeedsProgram chain the seed extractor + image extractor into
# the sweep so users don't have to remember to run either by hand. Requires a
# project that has been through SeedFunctions signal D (so c_int00 exists),
# Materialize{Sections,CopyTable} (so ramfunc bytes are present at run addrs),
# and MarkComponentRegistry's PIE + registry passes (so seed sources fire). If
# any is missing the extractors still run but emit near-empty outputs -- the
# throws below catch the two hard cases (no seeds / no image bytes).
$imageBin = ""
$imageMap = ""
$functionsTsv = ""
if ($AnalyzedMode) {
  $seedsAuto    = Join-Path $OutDir "seeds_auto.tsv"
  $imageBin     = Join-Path $OutDir "image.bin"
  $imageMap     = Join-Path $OutDir "image_map.tsv"
  $functionsTsv = Join-Path $OutDir "functions.tsv"
  $projDir  = Split-Path -Parent $SeedsProject
  $projName = [IO.Path]::GetFileNameWithoutExtension($SeedsProject)
  $wsSeeds  = Join-Path $Work "seedxtract"
  Remove-Item -Recurse -Force $wsSeeds -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force "$wsSeeds\scripts" | Out-Null
  Copy-Item "$Module\ghidra_scripts\DumpFwParitySeeds.java"     "$wsSeeds\scripts\" -Force
  Copy-Item "$Module\ghidra_scripts\DumpFwParityImage.java"     "$wsSeeds\scripts\" -Force
  Copy-Item "$Module\ghidra_scripts\DumpFwParityFunctions.java" "$wsSeeds\scripts\" -Force
  # All three scripts read -D options via getScriptArgs() and System.getProperty.
  # JAVA_TOOL_OPTIONS is the survivable path for the latter, since analyzeHeadless
  # drops everything after `=` in the -postScriptArgs CLI form.
  $savedJTO = $env:JAVA_TOOL_OPTIONS
  $env:JAVA_TOOL_OPTIONS = "-Dc28x.parity.seeds.out=$seedsAuto -Dc28x.parity.image.bytes=$imageBin -Dc28x.parity.image.map=$imageMap -Dc28x.parity.functions.out=$functionsTsv"
  Push-Location $wsSeeds
  $prevEA = $ErrorActionPreference; $ErrorActionPreference = "Continue"
  try {
    & "$Ghidra\support\analyzeHeadless.bat" $projDir $projName `
      -process $SeedsProgram -readOnly -noanalysis `
      -scriptPath "$wsSeeds\scripts" `
      -postScript DumpFwParitySeeds.java `
      -postScript DumpFwParityImage.java `
      -postScript DumpFwParityFunctions.java `
      -max-cpu 2 2>&1 | Out-Null
  } finally {
    $ErrorActionPreference = $prevEA
    Pop-Location
    $env:JAVA_TOOL_OPTIONS = $savedJTO
  }
  if (-not (Test-Path $seedsAuto)) { throw "seed extractor produced no output -- is $SeedsProgram in project $SeedsProject analyzed?" }
  if (-not (Test-Path $imageBin) -or -not (Test-Path $imageMap)) { throw "image extractor produced no output -- is $SeedsProgram in project $SeedsProject analyzed?" }
  if (-not (Test-Path $functionsTsv)) { throw "functions extractor produced no output" }
  Load-SeedsFile $seedsAuto "auto"
}
foreach ($s in $Seed) {
  $seedList.Add(@{ addr = (Parse-HexAddr $s); src = "explicit" }) | Out-Null
}
if ($Seeds) { Load-SeedsFile $Seeds "file" }
if ($seedList.Count -eq 0) { throw "no seeds -- give -Seed, -Seeds, or -SeedsProject+-SeedsProgram" }
Write-Host ("Loaded {0} seed(s)" -f $seedList.Count)

# ---------- image cache + word-address lookup --------------------------------
# In FLASH-ONLY mode $imgBytes is the raw firmware and there is one implicit
# block starting at $Base with $imgBytes.Length/2 words. In ANALYZED-PROGRAM
# mode $imgBytes is the concatenated bytes of every initialized block from the
# analyzed program (flash + materialized RAM), addressed through $imgBlocks.
if ($AnalyzedMode) {
  $imgBytes = [IO.File]::ReadAllBytes($imageBin)
  $imgBlocks = New-Object System.Collections.Generic.List[object]
  foreach ($ln in Get-Content -LiteralPath $imageMap) {
    $t = ($ln -split '#',2)[0].Trim()
    if (-not $t) { continue }
    $p = $t -split "\s+", 4
    if ($p.Count -lt 3) { continue }
    $imgBlocks.Add(@{
      wStart  = (Parse-HexAddr $p[0])
      wLen    = [int]$p[1]
      byteOff = [int]$p[2]
      name    = if ($p.Count -ge 4) { $p[3] } else { "" }
    }) | Out-Null
  }
  if ($imgBlocks.Count -eq 0) { throw "image_map.tsv had no valid rows: $imageMap" }
  Write-Host ("Loaded image: {0} bytes across {1} initialized block(s)" -f $imgBytes.Length, $imgBlocks.Count)
} else {
  $imgBytes = [IO.File]::ReadAllBytes($Fw)
  $imgBlocks = New-Object System.Collections.Generic.List[object]
  $imgBlocks.Add(@{
    wStart  = $Base
    wLen    = [int]($imgBytes.Length / 2)
    byteOff = 0
    name    = "flash"
  }) | Out-Null
}

# Resolve a word address to a (byteOff, wordsAvailable) pair, or $null if the
# address is outside every initialized block. wordsAvailable caps a slice at
# the block boundary so we never sew adjacent blocks together across a gap.
function Resolve-Word([int]$wordAddr) {
  foreach ($b in $imgBlocks) {
    if ($wordAddr -ge $b.wStart -and $wordAddr -lt ($b.wStart + $b.wLen)) {
      $off  = [int]$b.byteOff + ($wordAddr - $b.wStart) * 2
      $avail = $b.wStart + $b.wLen - $wordAddr
      return @{ byteOff = $off; wordsAvail = $avail; block = $b.name }
    }
  }
  return $null
}

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

# The worker body: no side effects, no file writes -- decoding a region is a
# pure function from (seed, src, image, config) to a result hashtable. The
# main thread does all file I/O after collecting the level's results. That is
# what makes ForEach-Object -Parallel safe: N runspaces write nothing shared.
#
# The body is stored as a STRING (not a scriptblock literal) because
# ForEach-Object -Parallel explicitly refuses to accept scriptblock variables
# via $using: (it warns "A ForEach-Object -Parallel using variable cannot be a
# script block ... can result in undefined behavior"). Both branches -- serial
# and parallel -- rehydrate the string via [scriptblock]::Create so the exact
# same body runs either way. Resolve-Word-equivalent logic is inlined so
# runspaces don't need to inherit parent-scope functions.
$DecodeSource = @'
param($seed, $src, $imgBytesRef, $imgBlocks, $maxSpan, $workDir, $tiBin, $endMnems, $callMnems)

  # inline Resolve-Word: returns @{byteOff, wordsAvail, name} or $null
  $res = $null
  foreach ($b in $imgBlocks) {
    if ($seed -ge $b.wStart -and $seed -lt ($b.wStart + $b.wLen)) {
      $res = @{
        byteOff    = [int]$b.byteOff + ($seed - $b.wStart) * 2
        wordsAvail = $b.wStart + $b.wLen - $seed
        name       = $b.name
      }
      break
    }
  }
  if (-not $res) {
    return @{ seed = $seed; src = $src; skip = "OOR"; targets = @() }
  }

  $span = [Math]::Min($maxSpan, [int]$res.wordsAvail)
  $bytes = New-Object byte[] ($span * 2)
  [Array]::Copy($imgBytesRef, [int]$res.byteOff, $bytes, 0, $span * 2)

  # Per-worker filenames -- ForEach-Object -Parallel runs N runspaces on the
  # SAME cwd, so a shared region.asm/region.obj would race. Encoding the seed
  # word in the filename makes each concurrent asm2000 self-contained.
  $tag = "reg_{0:x8}" -f $seed
  $regAsm = Join-Path $workDir "$tag.asm"
  $regObj = Join-Path $workDir "$tag.obj"
  $sb = [Text.StringBuilder]::new(); [void]$sb.AppendLine("        .text")
  for ($i = 0; $i -lt $span; $i++) {
    $w = [int]$bytes[$i*2] + [int]$bytes[$i*2+1]*256
    [void]$sb.AppendLine(("        .word 0x{0:x4}" -f $w))
  }
  [IO.File]::WriteAllText($regAsm, $sb.ToString())

  Push-Location $workDir
  try {
    & "$tiBin\asm2000.exe" -v28 (Split-Path -Leaf $regAsm) -o=(Split-Path -Leaf $regObj) 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $regObj)) {
      return @{ seed = $seed; src = $src; skip = "ASM_FAIL"; targets = @() }
    }
    $dis = & "$tiBin\dis2000.exe" -i (Split-Path -Leaf $regObj) 2>&1
  } finally {
    Pop-Location
    Remove-Item -LiteralPath $regAsm,$regObj -ErrorAction SilentlyContinue
  }

  $endWrel = -1
  $lines = New-Object System.Collections.Generic.List[string]
  $targets = New-Object System.Collections.Generic.List[int]
  $unresolved = New-Object System.Collections.Generic.List[string]
  foreach ($ln in $dis) {
    if ($ln -match '^\s*([0-9a-fA-F]{8})\s+[0-9a-fA-F]{4}\s+(\|\|)?\s*([A-Z][A-Z0-9_]*)\s*(.*)$') {
      $wrel = [Convert]::ToInt32($Matches[1], 16)
      $mnem = $Matches[3].ToUpper()
      $ops  = ($Matches[4].TrimEnd() -replace '\s+',' ')
      $wa   = $seed + $wrel
      $text = if ($ops) { "$mnem $ops" } else { $mnem }
      $lines.Add(("{0:x8}`t{1:x8}`t{2}" -f $seed, $wa, $text)) | Out-Null
      if ($callMnems.Contains($mnem)) {
        foreach ($tok in ($ops -split '[\s,]+')) {
          if ($tok -match '^0[xX]([0-9a-fA-F]+)') {
            $t = [Convert]::ToInt32($Matches[1], 16)
            # inline Resolve check
            $ok = $false
            foreach ($b in $imgBlocks) {
              if ($t -ge $b.wStart -and $t -lt ($b.wStart + $b.wLen)) { $ok = $true; break }
            }
            if ($ok) { $targets.Add($t) }
            else { $unresolved.Add(("oor-call`t0x{0:x}`tfrom=0x{1:x}" -f $t, $wa)) }
            break
          }
        }
      }
      if ($endMnems.Contains($mnem)) { $endWrel = $wrel; break }
    }
  }
  $lenWords = if ($endWrel -ge 0) { $endWrel + 1 } else {
    $unresolved.Add(("no-return-hit`t0x{0:x}`tspan={1}`t{2}" -f $seed, $span, $src)) | Out-Null
    $span
  }
  return @{
    seed       = $seed
    src        = $src
    lenWords   = $lenWords
    lines      = $lines.ToArray()
    targets    = $targets.ToArray()
    unresolved = $unresolved.ToArray()
  }
'@
$DecodeBlock = [scriptblock]::Create($DecodeSource)

# Persist a batch of worker results and enqueue their targets. Runs serially in
# the main thread; all file writes go through here so nothing contends.
function Persist-BatchResults($results) {
  $regionLines     = New-Object System.Collections.Generic.List[string]
  $dumpLines       = New-Object System.Collections.Generic.List[string]
  $unresolvedLines = New-Object System.Collections.Generic.List[string]
  foreach ($r in $results) {
    if ($r.skip) {
      $regionLines.Add(("0x{0:x}`t0`t{1}:{2}" -f $r.seed, $r.skip, $r.src)) | Out-Null
      continue
    }
    $regionLines.Add(("0x{0:x}`t{1}`t{2}" -f $r.seed, $r.lenWords, $r.src)) | Out-Null
    foreach ($ln in $r.lines) { $dumpLines.Add($ln) | Out-Null }
    $dumpLines.Add(("{0:x8}`tEOR`t{1}" -f $r.seed, $r.lenWords)) | Out-Null
    foreach ($u in $r.unresolved) { $unresolvedLines.Add($u) | Out-Null }
    foreach ($t in $r.targets) {
      if ($visited.Contains($t)) { continue }
      $queue.Enqueue(@{ addr = $t; src = ("from:0x{0:x}" -f $r.seed) }) | Out-Null
    }
  }
  if ($regionLines.Count     -gt 0) { Add-Content -LiteralPath $regionsTsv    -Value $regionLines.ToArray() }
  if ($dumpLines.Count       -gt 0) { Add-Content -LiteralPath $tiDumpTsv     -Value $dumpLines.ToArray() }
  if ($unresolvedLines.Count -gt 0) { Add-Content -LiteralPath $unresolvedTsv -Value $unresolvedLines.ToArray() }
}

$useParallel = ($Parallel -gt 1 -and $PSVersionTable.PSVersion.Major -ge 7)
if ($Parallel -gt 1 -and -not $useParallel) {
  Write-Warning "-Parallel $Parallel ignored: needs PowerShell 7+, current is $($PSVersionTable.PSVersion). Running serial."
}
Write-Host ("BFS: {0}" -f ($(if ($useParallel) { "parallel x$Parallel" } else { "serial" })))

$processed = 0
while ($queue.Count -gt 0) {
  # Drain the current queue into a level and dedup against visited. Level-based
  # BFS is what makes parallel decode safe -- every seed in the batch is
  # independent because we've already committed to visiting all of them.
  $level = New-Object System.Collections.Generic.List[object]
  while ($queue.Count -gt 0) {
    $e = $queue.Dequeue()
    if ($visited.Contains($e.addr)) { continue }
    $visited[$e.addr] = $true
    $level.Add(@{ addr = [int]$e.addr; src = [string]$e.src }) | Out-Null
  }
  if ($level.Count -eq 0) { break }

  if ($useParallel) {
    # Rehydrate the decode body per runspace from its source string ($using:
    # forbids scriptblock values), and invoke with positional args pulled from
    # $using: primitives. The parallel workers each build the scriptblock
    # exactly once and then reuse it for every $_ they process in that runspace.
    $results = $level | ForEach-Object -Parallel {
      $blk = [scriptblock]::Create($using:DecodeSource)
      & $blk $_.addr $_.src $using:imgBytes $using:imgBlocks $using:MaxSpan $using:Work $using:TiBin $using:endMnems $using:callMnems
    } -ThrottleLimit $Parallel
  } else {
    $results = foreach ($e in $level) {
      & $DecodeBlock $e.addr $e.src $imgBytes $imgBlocks $MaxSpan $Work $TiBin $endMnems $callMnems
    }
  }
  Persist-BatchResults $results
  $processed += $level.Count
}
Write-Host ("BFS: {0} seed(s) processed, {1} region(s) recorded" -f $processed, ((Get-Content $regionsTsv).Count))

# ---------- our-side decode: ONE headless call for all regions ------------
# ANALYZED-PROGRAM mode: -process against the analyzed program (so RAM-resident
# ramfunc bytes are readable at their run addresses -- a fresh import of the
# raw .bin has zeroes there).
# FLASH-ONLY mode: -import the raw .bin at $Base with BinaryLoader; ramfunc
# regions are unreachable but the flash coverage is complete.
$ws = Join-Path $Work "run"
Remove-Item -Recurse -Force $ws -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force "$ws\scripts" | Out-Null
Copy-Item "$Module\ghidra_scripts\DumpFwParityOurs.java" "$ws\scripts\" -Force
$ourDump = Join-Path $OutDir "our_dump.tsv"
Remove-Item -LiteralPath $ourDump -ErrorAction SilentlyContinue

$savedJTO = $env:JAVA_TOOL_OPTIONS
$env:JAVA_TOOL_OPTIONS = "-Dc28x.parity.regions.in=$regionsTsv -Dc28x.parity.regions.out=$ourDump"
$prevEA = $ErrorActionPreference; $ErrorActionPreference = "Continue"
try {
  if ($AnalyzedMode) {
    $projDir  = Split-Path -Parent $SeedsProject
    $projName = [IO.Path]::GetFileNameWithoutExtension($SeedsProject)
    & "$Ghidra\support\analyzeHeadless.bat" $projDir $projName `
      -process $SeedsProgram -readOnly -noanalysis `
      -scriptPath "$ws\scripts" -postScript DumpFwParityOurs.java `
      -max-cpu 2 2>&1 | Out-Null
  } else {
    New-Item -ItemType Directory -Force "$ws\proj" | Out-Null
    # BinaryLoader with -loader-baseAddr for the correct absolute base. The flag
    # is in WORDS (matches every other address in the wordsize=2 space; see
    # docs/C28X_IMAGE_SETUP.md and docs/ANALYSIS-MIGRATION.md). Without it every
    # region's start_word points outside the (address-0) block and the sweep
    # degrades to all MISS_MEM.
    $baseWord = "0x{0:x}" -f $Base
    Push-Location $ws
    try {
      & "$Ghidra\support\analyzeHeadless.bat" "$ws\proj" ("bs_" + (Split-Path -Leaf $Fw)) `
        -import $Fw -processor "TMS320C28x:LE:32:default" `
        -loader BinaryLoader -loader-baseAddr $baseWord `
        -scriptPath "$ws\scripts" -postScript DumpFwParityOurs.java -noanalysis -overwrite `
        -max-cpu 2 2>&1 | Out-Null
    } finally { Pop-Location }
  }
} finally {
  $ErrorActionPreference = $prevEA
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

# ---------- reachability diff (analyzed mode only) ---------------------------
# For every region BFS visited (via regions.tsv), check whether our analyzer
# has a function at that entry. Presence = the analyzer independently rooted
# the same thing dis2000-driven flow reached. Absence = a function dis2000
# reaches from data-side seeds that our analyzer never bound as a function
# entry: usually an inbound call our decoder didn't recognize (a call-shaped
# encoding that decodes as something else, or a call-fixup we're missing).
$unrootedTsv = ""
if ($AnalyzedMode) {
  $ourFns = New-Object System.Collections.Generic.HashSet[int]
  foreach ($ln in @(Get-Content -LiteralPath $functionsTsv)) {
    $t = ($ln -split '#',2)[0].Trim()
    if (-not $t) { continue }
    $col1 = ($t -split "\t")[0]
    [void]$ourFns.Add((Parse-HexAddr $col1))
  }
  $unrootedTsv = Join-Path $OutDir "unrooted.tsv"
  $u = New-Object System.Collections.Generic.List[string]
  $u.Add("# entry_word`tsource_of_reach") | Out-Null
  $unrootedCount = 0
  foreach ($ln in @(Get-Content -LiteralPath $regionsTsv)) {
    $p = ([string]$ln) -split "`t", 3
    if ($p.Count -lt 3) { continue }
    $src = $p[2]
    if ($src -like "OOR:*" -or $src -like "ASM_FAIL:*") { continue }
    $wa = Parse-HexAddr $p[0]
    if (-not $ourFns.Contains($wa)) {
      $u.Add(("0x{0:x}`t{1}" -f $wa, $src)) | Out-Null
      $unrootedCount++
    }
  }
  Set-Content -LiteralPath $unrootedTsv -Value $u.ToArray() -Encoding ascii
  $rl.Add("") | Out-Null
  $rl.Add(("--- REACHABILITY (BFS-visited entries NOT bound as functions: {0}) ---" -f $unrootedCount)) | Out-Null
  # Show only the first 30 to keep the report scannable; full list in unrooted.tsv.
  $shown = 0
  foreach ($ln in @(Get-Content -LiteralPath $unrootedTsv)) {
    if ($shown -ge 30) { break }
    $t = ($ln -split '#',2)[0].Trim()
    if (-not $t) { continue }
    $rl.Add("  $t") | Out-Null
    $shown++
  }
  Write-Host ("  reachability: {0} BFS entries not bound as functions" -f $unrootedCount) -ForegroundColor Yellow
}

Set-Content -LiteralPath $report -Value $rl.ToArray() -Encoding ascii

Write-Host ("  regions:  {0}" -f $regionsTsv)
Write-Host ("  TI dump:  {0}" -f $tiDumpTsv)
Write-Host ("  our dump: {0}" -f $ourDump)
Write-Host ("  report:   {0}" -f $report)
if ($unrootedTsv) { Write-Host ("  unrooted: {0}" -f $unrootedTsv) }
