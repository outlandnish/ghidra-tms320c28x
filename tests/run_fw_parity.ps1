# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
# Firmware decode-parity: dis2000 (TI ground truth) vs our SLEIGH .sla, over a WORD
# range of a byte-swapped C28x firmware image. Checks REAL firmware functions (e.g.
# the AES / immobilizer routines the emulation-fidelity work targets).
#
# How it works:
#   1. slice [Start, Start+Count) words out of the swapped image (byte off = (w-Base)*2),
#   2. emit them as `.word` directives, assemble with asm2000 -> a COFF2 object,
#   3. dis2000 -i (data_as_text) that object => TI ground-truth listing,
#   4. headless-disassemble the same raw words with our installed .sla (DumpParity.java),
#   5. align on word address; report WRONG mnemonics / UNDEF / length-skew, plus a
#      side-by-side listing so operand-level (semantic) gaps can be eyeballed.
#
# A WRONG mnemonic or length-skew is a decode bug. Operand-text diffs are mostly cosmetic
# (hex vs dec, Ghidra's '@' register-direct marker, relative vs absolute branch targets);
# the ones that matter are unresolved placeholders like `mem32` / `*loc16`, which flag a
# decode-only constructor whose p-code is empty -- fatal for emulation, invisible to the
# decompiler.
#
# Usage:
#   pwsh -File tests\run_fw_parity.ps1 -Fw <swapped.bin> -Start 0x9af9e -Count 0xf2 -Tag aes
param(
  [Parameter(Mandatory)][string]$Fw,             # swapped firmware image on disk
  [Parameter(Mandatory)][int]$Start,             # first WORD address (e.g. 0x9af9e)
  [Parameter(Mandatory)][int]$Count,             # number of words to cover
  [int]$Base    = 0x82000,                        # image base word address
  [string]$Tag  = "fn",
  [string]$Ghidra = $env:GHIDRA_INSTALL_DIR,
  [string]$Ti     = $env:C2000WARE,
  [string]$Module = (Split-Path -Parent $PSScriptRoot),
  [string]$Work   = $null
)
# Load this worktree's local config (.c28x.env), then re-resolve -Ghidra/-Ti from
# it when not passed explicitly. Absent file => no-op.
. "$PSScriptRoot\_env.ps1"
Import-C28xEnv $Module
if (-not $PSBoundParameters.ContainsKey('Ghidra')) { $Ghidra = $env:GHIDRA_INSTALL_DIR }
if (-not $PSBoundParameters.ContainsKey('Ti'))     { $Ti     = $env:C2000WARE }
# Per-worktree scratch dir (was a fixed "$env:TEMP\c28x-fwparity" that collided across worktrees).
if (-not $Work)   { $Work = Get-C28xScratchRoot -Module $Module -Kind "fwparity" }
if (-not $Ti)     { throw "Point -Ti (or `$env:C2000WARE / .c28x.env) at your TI C2000 CGT install (with bin\asm2000.exe, bin\dis2000.exe)." }
if (-not $Ghidra) { throw "Point -Ghidra (or `$env:GHIDRA_INSTALL_DIR / .c28x.env) at your Ghidra install." }
$ErrorActionPreference = "Stop"
$TiBin = "$Ti\bin"
New-Item -ItemType Directory -Force $Work | Out-Null

# --- 1/2. slice words -> .word asm -> asm2000 obj ----------------------------
$img = [IO.File]::ReadAllBytes($Fw)
$off = ($Start - $Base) * 2
if ($off -lt 0 -or ($off + $Count*2) -gt $img.Length) { throw "range [0x$($Start.ToString('x')),+$Count) is outside the image" }
$bin = Join-Path $Work "$Tag.bin"
$asm = Join-Path $Work "$Tag.asm"
$slice = New-Object byte[] ($Count*2)
[Array]::Copy($img, $off, $slice, 0, $Count*2)
[IO.File]::WriteAllBytes($bin, $slice)
$sb = [Text.StringBuilder]::new(); [void]$sb.AppendLine("        .text")
for ($i=0; $i -lt $Count; $i++) {
  # NB: build the 16-bit word with int math -- `[byte] -bor ([byte] -shl 8)` truncates
  # the high byte back to a byte in PowerShell and silently zeroes it.
  $w = [int]$slice[$i*2] + [int]$slice[$i*2+1]*256
  [void]$sb.AppendLine(("        .word 0x{0:x4}" -f $w))
}
[IO.File]::WriteAllText($asm, $sb.ToString())

# --- 3. TI ground truth: dis2000 -i (force .text-as-code) --------------------
Push-Location $Work
& "$TiBin\asm2000.exe" -v28 "$Tag.asm" -o="$Tag.obj" 2>&1 | Out-Null
$dis = & "$TiBin\dis2000.exe" -i "$Tag.obj" 2>&1
Pop-Location
$tiTxt = @{}; $tiMnem = @{}
foreach ($ln in $dis) {
  if ($ln -match '^\s*([0-9a-fA-F]{8})\s+([0-9a-fA-F]{4})\s+([A-Z][A-Z0-9_]*)\s*(.*)$') {
    $wa = [Convert]::ToInt32($Matches[1],16) + $Start
    $mn = $Matches[3].ToUpper()
    $ops = ($Matches[4].TrimEnd() -replace '\s+',' ')
    $tiTxt[$wa]  = ("{0} {1}" -f $mn,$ops).Trim()
    $tiMnem[$wa] = $mn
  }
}

# --- 4. our SLEIGH via headless ----------------------------------------------
$ws = "$Work\run"; Remove-Item -Recurse -Force $ws -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force "$ws\proj","$ws\scripts" | Out-Null
Copy-Item "$Module\ghidra_scripts\DumpParity.java" "$ws\scripts\" -Force
$outTxt = "$Work\$Tag.ours.txt"; Remove-Item $outTxt -ErrorAction SilentlyContinue
# This Ghidra rejects `-D...` on the analyzeHeadless CLI; pass the system property via
# the JVM env instead (DumpParity reads -Dc28x.parity.out).
$savedJTO = $env:JAVA_TOOL_OPTIONS
$env:JAVA_TOOL_OPTIONS = "-Dc28x.parity.out=$outTxt"
Push-Location $ws
& "$Ghidra\support\analyzeHeadless.bat" "$ws\proj" "t_$Tag" `
  -import $bin -processor "TMS320C28x:LE:32:default" `
  -scriptPath "$ws\scripts" -postScript DumpParity.java -noanalysis -overwrite `
  -max-cpu 2 2>&1 | Out-Null
Pop-Location
$env:JAVA_TOOL_OPTIONS = $savedJTO
if (-not (Test-Path $outTxt)) { throw "headless dump produced no output" }
$ourTxt = @{}; $ourMnem = @{}
foreach ($ln in Get-Content $outTxt) {
  $p = $ln -split "`t"
  if ($p.Count -ge 2) {
    $wa = [Convert]::ToInt32($p[0],16) + $Start
    $ourTxt[$wa]  = ($p[1].Trim() -replace '\s+',' ')
    $ourMnem[$wa] = (($p[1] -split '\s+')[0]).ToUpper()
  }
}

# --- 5. align + report -------------------------------------------------------
$agree=0; $wrong=@(); $undef=@(); $skew=@()
foreach ($w in ($tiTxt.Keys | Sort-Object)) {
  if (-not $ourMnem.ContainsKey($w)) { $skew += $w; continue }
  $o = $ourMnem[$w]
  if ($o -eq "<UNDEF>") { $undef += $w }
  elseif ($o -eq $tiMnem[$w]) { $agree++ }
  else { $wrong += $w }
}
Write-Host ("=== FW PARITY {0} @0x{1:x}..0x{2:x} ({3} words) ===" -f $Tag,$Start,($Start+$Count-1),$Count) -ForegroundColor Cyan
Write-Host ("  TI mnem-lines: {0}   agree: {1}   WRONG-mnem: {2}   UNDEF: {3}   skew: {4}" -f $tiTxt.Count,$agree,$wrong.Count,$undef.Count,$skew.Count)
if ($wrong.Count) {
  Write-Host "`n  --- WRONG MNEMONICS (decode bug) ---" -ForegroundColor Red
  foreach ($w in $wrong) { Write-Host ("    0x{0:x5}  TI=[{1}]  ours=[{2}]" -f $w,$tiTxt[$w],$ourTxt[$w]) }
}
if ($undef.Count) {
  Write-Host "`n  --- UNDEF (ours failed to decode) ---" -ForegroundColor Yellow
  foreach ($w in $undef) { Write-Host ("    0x{0:x5}  TI=[{1}]" -f $w,$tiTxt[$w]) }
}
if ($skew.Count) {
  Write-Host "`n  --- LENGTH SKEW (instr-length disagreement) ---" -ForegroundColor DarkYellow
  foreach ($w in $skew) { Write-Host ("    0x{0:x5}  TI=[{1}]" -f $w,$tiTxt[$w]) }
}
$opdiff = @()
foreach ($w in ($tiTxt.Keys | Sort-Object)) {
  if ($ourTxt.ContainsKey($w) -and $ourMnem[$w] -eq $tiMnem[$w]) {
    if (($tiTxt[$w].ToUpper() -replace '[ ,]','') -ne ($ourTxt[$w].ToUpper() -replace '[ ,]','')) { $opdiff += $w }
  }
}
Write-Host ("`n  operand-text diffs (same mnemonic): {0}  (mostly cosmetic; grep the side-by-side for mem32/*loc16)" -f $opdiff.Count) -ForegroundColor Yellow
$sbs = Join-Path $Work "$Tag.sidebyside.txt"
$lines = foreach ($w in ($tiTxt.Keys | Sort-Object)) {
  $ourStr = if ($ourTxt.ContainsKey($w)) { $ourTxt[$w] } else { "(skew)" }
  $mk = if (-not $ourMnem.ContainsKey($w)) { " <<<SKEW" }
        elseif ($ourMnem[$w] -ne $tiMnem[$w]) { " <<<MNEM" }
        elseif (($tiTxt[$w].ToUpper() -replace '[ ,]','') -ne ($ourStr.ToUpper() -replace '[ ,]','')) { " <<<OPS" }
        else { "" }
  "{0:x5}  TI: {1,-32} | OURS: {2}{3}" -f $w, $tiTxt[$w], $ourStr, $mk
}
$lines | Out-File $sbs -Encoding ascii
Write-Host ("  side-by-side: {0}" -f $sbs)