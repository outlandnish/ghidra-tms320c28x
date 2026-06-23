# TI ground-truth parity test for the C28x SLEIGH module.
#
# THE key correctness tool. For a given TI runtime-lib object (real TI-compiled C28x
# code), this:
#   1. extracts the object from rts2800_fpu32.lib and runs TI's own dis2000 on it,
#   2. parses the COFF2 .text into a raw word bin,
#   3. headless-disassembles that bin with OUR freshly-installed .sla,
#   4. aligns both on word address and reports mnemonic agreement, WRONG decodes
#      (we decoded but disagree with TI), and UNDEFs (we failed to decode).
#
# A WRONG decode is a spec bug. An UNDEF is just a missing opcode. The bar is:
# ZERO wrong decodes; minimize UNDEFs.
#
# Usage:
#   pwsh -File tests\run_ti_parity.ps1 [-Obj k_expf.c.obj] [-Ghidra <dir>] [-Ti <dir>]
param(
  [string]$Obj    = "k_expf.c.obj",
  [string]$Ghidra = $env:GHIDRA_INSTALL_DIR,
  [string]$Ti     = "C:\Users\nisha\Downloads\ti-cgt-c2000_25.11.0.LTS",
  [string]$Module = (Split-Path -Parent $PSScriptRoot)
)
if (-not $Ghidra) { $Ghidra = "C:\Users\nisha\Downloads\ghidra_12.1.2_PUBLIC_20260605\ghidra_12.1.2_PUBLIC" }
$ErrorActionPreference = "Stop"
$bin = "$Ti\bin"; $lib = "$Ti\lib\rts2800_fpu32.lib"
$work = "$env:TEMP\c28x-parity"; New-Item -ItemType Directory -Force $work | Out-Null
$base = [IO.Path]::GetFileNameWithoutExtension($Obj)   # e.g. "k_expf.c"

# --- 1. TI ground truth -------------------------------------------------------
Push-Location $work
& "$bin\ar2000.exe" x $lib $Obj
& "$bin\dis2000.exe" $Obj | Out-File "$base.dis2000.txt" -Encoding ascii
Pop-Location

# --- 2. COFF2 .text -> raw word bin -------------------------------------------
$bytes = [IO.File]::ReadAllBytes("$work\$Obj")
function U16($o){ $bytes[$o] -bor ($bytes[$o+1] -shl 8) }
function U32($o){ $bytes[$o] -bor ($bytes[$o+1] -shl 8) -bor ($bytes[$o+2] -shl 16) -bor ($bytes[$o+3] -shl 24) }
$magic = U16 0
if ($magic -ne 0x00c2) { throw ("not a COFF2 object (magic=0x{0:x4})" -f $magic) }
$nscns  = U16 2
$opthdr = U16 16
$shoff  = 22 + $opthdr
$textBin = Join-Path "$Module\tests" ("ti_" + ($base -replace '\.','_') + "_text.bin")
$found = $false
for ($i=0; $i -lt $nscns; $i++) {
  $s = $shoff + $i*48
  $name = ([Text.Encoding]::ASCII.GetString($bytes[$s..($s+7)]) -replace "`0","").Trim()
  if ($name -eq ".text") {
    $sizeWords = U32 ($s+16)   # COFF2 section size is in WORDS for C28x
    $scnptr    = U32 ($s+20)
    $nbytes    = $sizeWords * 2
    $slice = New-Object byte[] $nbytes
    [Array]::Copy($bytes, $scnptr, $slice, 0, $nbytes)
    [IO.File]::WriteAllBytes($textBin, $slice)
    Write-Host ("  .text: {0} words ({1} bytes) at file offset 0x{2:x}" -f $sizeWords,$nbytes,$scnptr)
    $found = $true; break
  }
}
if (-not $found) { throw "no .text section in $Obj" }

# --- 3. our SLEIGH disasm via headless ----------------------------------------
$ws = "$work\run"; Remove-Item -Recurse -Force $ws -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force "$ws\proj","$ws\scripts" | Out-Null
Copy-Item "$Module\ghidra_scripts\DumpParity.java" "$ws\scripts\" -Force
$outTxt = "$work\ours_parity.txt"; Remove-Item $outTxt -ErrorAction SilentlyContinue
Push-Location $ws
& "$Ghidra\support\analyzeHeadless.bat" "$ws\proj" t `
  -import $textBin -processor "TMS320C28x:LE:32:default" `
  -scriptPath "$ws\scripts" -postScript DumpParity.java -noanalysis -overwrite `
  -max-cpu 2 "-Dc28x.parity.out=$outTxt" 2>&1 | Out-Null
Pop-Location
if (-not (Test-Path $outTxt)) { throw "headless dump produced no output" }

# --- 4. align + report --------------------------------------------------------
# TI ground truth: lines "<8hex word>   <hexword>   <MNEMONIC> ...". Continuation
# words have an opcode but NO mnemonic field; we key on the mnemonic-bearing lines.
$ti = @{}
foreach ($ln in Get-Content "$work\$base.dis2000.txt") {
  if ($ln -match '^\s*([0-9a-fA-F]{8})\s+[0-9a-fA-F]{4}\s+([A-Z][A-Z0-9_]+)') {
    $w = [Convert]::ToInt64($Matches[1],16)
    if (-not $ti.ContainsKey($w)) { $ti[$w] = $Matches[2].ToUpper() }
  }
}
$ours = @{}
foreach ($ln in Get-Content $outTxt) {
  $p = $ln -split "`t"
  if ($p.Count -ge 2) {
    $w = [Convert]::ToInt64($p[0],16)
    $ours[$w] = (($p[1] -split '\s+')[0]).ToUpper()
  }
}

$agree=0; $wrong=@(); $undef=@(); $missing=@()
foreach ($w in ($ti.Keys | Sort-Object)) {
  if (-not $ours.ContainsKey($w)) { $missing += $w; continue }
  $o = $ours[$w]
  if ($o -eq "<UNDEF>") { $undef += $w }
  elseif ($o -eq $ti[$w]) { $agree++ }
  else { $wrong += [pscustomobject]@{ Word=$w; TI=$ti[$w]; Ours=$o } }
}
$tot = $ti.Count
Write-Host ""
Write-Host ("=== TI PARITY: {0} ===" -f $Obj) -ForegroundColor Cyan
Write-Host ("  TI instructions:  {0}" -f $tot)
Write-Host ("  agree:            {0}  ({1:N1}%)" -f $agree, (100.0*$agree/$tot)) -ForegroundColor Green
Write-Host ("  UNDEF (missing op): {0}" -f $undef.Count) -ForegroundColor Yellow
Write-Host ("  WRONG (spec bug): {0}" -f $wrong.Count) -ForegroundColor $(if($wrong.Count){"Red"}else{"Green"})
if ($missing.Count) { Write-Host ("  unaligned (multi-word skew): {0}" -f $missing.Count) -ForegroundColor DarkYellow }
if ($wrong.Count) {
  Write-Host "`n  --- WRONG DECODES (TI vs ours) ---" -ForegroundColor Red
  $wrong | ForEach-Object { Write-Host ("    0x{0:x4}  TI={1,-12} ours={2}" -f $_.Word,$_.TI,$_.Ours) }
}
if ($undef.Count) {
  Write-Host "`n  --- UNDEF words (opcodes still to add) ---" -ForegroundColor Yellow
  $undef | ForEach-Object {
    $line = (Get-Content "$work\$base.dis2000.txt" | Select-String ("^\s*{0:x8}\s" -f $_))
    Write-Host ("    0x{0:x4}  TI: {1}" -f $_, (($line -replace '\s+',' ').Trim()))
  }
}
