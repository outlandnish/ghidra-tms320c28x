# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
# C28x SLEIGH disassembler regression test (run from PowerShell).
#
# 1. Recompiles the .sla, 2. reinstalls it into Ghidra, then for each case in
# $Cases: 3. headless-disassembles tests/<case>.bin, 4. diffs the mnemonic text
# against tests/<case>.expected.txt.
#
# Cases:
#   addr_modes   -- every AMODE=0 loc16/loc32 addressing mode (14 cases).
#   fpu_display  -- FPU operand RENDERING, where our text has to match TI's own
#                   assembler exactly: MOVST0's flag-select list, TESTTF's CNDF,
#                   and the split-field #16FHi immediates (whose value is spread
#                   across both instruction words, so a wrong reassembly prints a
#                   plausible-looking but wrong constant). Every expected line was
#                   verified against asm2000/dis2000 output for the same words.
#
# Usage:  pwsh -File tests\run_disasm_test.ps1 -Ghidra <ghidra-install-dir>
#   (Ghidra defaults to $env:GHIDRA_INSTALL_DIR; Module defaults to this repo root.)
param(
  [string]$Ghidra = $env:GHIDRA_INSTALL_DIR,
  [string]$Module = (Split-Path -Parent $PSScriptRoot),
  [string[]]$Cases = @("addr_modes", "fpu_display")
)
if (-not $Ghidra) { throw "Set -Ghidra or the GHIDRA_INSTALL_DIR env var to your Ghidra install." }
$ErrorActionPreference = "Stop"
$lang = "$Module\data\languages"
$tmp  = "$env:TEMP\c28x-test"

# 1. compile (UNC-safe: copy to a Windows-local dir, the .bat can't run from UNC cwd)
$bld = "$tmp\build"; New-Item -ItemType Directory -Force -Path $bld | Out-Null
Copy-Item "$lang\*" $bld -Force
Push-Location $bld
$null | & "$Ghidra\support\sleigh.bat" tms320c28x.slaspec
Pop-Location
if (-not (Test-Path "$bld\tms320c28x.sla")) { throw "SLEIGH compile failed (no .sla)" }
Copy-Item "$bld\tms320c28x.sla" $lang -Force

# 2. reinstall into Ghidra (Module.manifest too, so a fresh Ghidra recognizes the
# directory as a module and discovers the language)
$modroot = "$Ghidra\Ghidra\Processors\TMS320C28x"
$inst = "$modroot\data\languages"
New-Item -ItemType Directory -Force -Path $inst | Out-Null
Copy-Item "$lang\*" $inst -Force
Copy-Item "$Module\Module.manifest" "$modroot\Module.manifest" -Force

$ws = "$tmp\run"; New-Item -ItemType Directory -Force -Path "$ws\proj","$ws\scripts" | Out-Null
Copy-Item "$Module\ghidra_scripts\DumpDisasm.java" "$ws\scripts\DumpDisasm.java" -Force

$fail = 0
$total = 0
foreach ($name in $Cases) {
  Write-Host "=== $name ==="

  # 3. headless disassemble
  Copy-Item "$Module\tests\$name.bin" "$ws\$name.bin" -Force
  Push-Location $ws
  $raw = & "$Ghidra\support\analyzeHeadless.bat" "$ws\proj" "t_$name" `
    -import "$ws\$name.bin" -processor "TMS320C28x:LE:32:default" `
    -scriptPath "$ws\scripts" -postScript DumpDisasm.java -noanalysis -overwrite 2>&1
  Pop-Location

  # 4. compare. Pull "ADDR<tab>BYTES<tab>TEXT" lines, normalize, diff vs expected.
  # Match the DumpDisasm output lines between the BEGIN/END markers. Address may or may
  # not carry a space prefix (e.g. "CODE:0000" on split spaces, "0000" on unified ram),
  # so strip any "<word>:" prefix and leading zeros rather than hard-coding "CODE:".
  $got = $raw | Select-String "DumpDisasm.java> [0-9a-fA-F]" | ForEach-Object {
    ($_ -replace ".*DumpDisasm.java> ", "" -replace " \(GhidraScript\)\s*$","" `
        -replace "^[A-Za-z]+:0*", "0x" -replace "^0*([0-9a-fA-F])", "0x`$1").Trim()
  }
  $exp = Get-Content "$Module\tests\$name.expected.txt"
  "--- GOT ---"; $got
  for ($i=0; $i -lt $exp.Count; $i++) {
    $e = $exp[$i].Trim(); $g = if ($i -lt $got.Count) { $got[$i].Trim() } else { "<missing>" }
    # compare on the mnemonic text (3rd tab-field), tolerant of 0x formatting
    $et = ($e -split "`t")[2]; $gt = ($g -split "`t")[2]
    $etn = $et -replace "0x",""; $gtn = $gt -replace "0x",""
    if ($etn -ne $gtn) { Write-Host "FAIL $name line ${i}: expected [$et] got [$gt]" -ForegroundColor Red; $fail++ }
  }
  $total += $exp.Count
}

if ($fail -eq 0) { Write-Host "PASS: all $total cases" -ForegroundColor Green }
else { Write-Host "$fail FAILURES" -ForegroundColor Red; exit 1 }
