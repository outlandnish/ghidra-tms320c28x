# C28x SLEIGH disassembler regression test (run from PowerShell).
#
# 1. Recompiles the .sla, 2. reinstalls it into Ghidra, 3. headless-disassembles
# tests/addr_modes.bin, 4. diffs against tests/addr_modes.expected.txt.
#
# Usage:  pwsh -File tests\run_disasm_test.ps1 -Ghidra <ghidra-install-dir>
#   (Ghidra defaults to $env:GHIDRA_INSTALL_DIR; Module defaults to this repo root.)
param(
  [string]$Ghidra = $env:GHIDRA_INSTALL_DIR,
  [string]$Module = (Split-Path -Parent $PSScriptRoot)
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

# 2. reinstall into Ghidra
$inst = "$Ghidra\Ghidra\Processors\TMS320C28x\data\languages"
New-Item -ItemType Directory -Force -Path $inst | Out-Null
Copy-Item "$lang\*" $inst -Force

# 3. headless disassemble
$ws = "$tmp\run"; New-Item -ItemType Directory -Force -Path "$ws\proj","$ws\scripts" | Out-Null
Copy-Item "$Module\tests\addr_modes.bin" "$ws\addr_modes.bin" -Force
Copy-Item "$Module\ghidra_scripts\DumpDisasm.java" "$ws\scripts\DumpDisasm.java" -Force
Push-Location $ws
$raw = & "$Ghidra\support\analyzeHeadless.bat" "$ws\proj" t `
  -import "$ws\addr_modes.bin" -processor "TMS320C28x:LE:32:default" `
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
$exp = Get-Content "$Module\tests\addr_modes.expected.txt"
"--- GOT ---"; $got
$fail = 0
for ($i=0; $i -lt $exp.Count; $i++) {
  $e = $exp[$i].Trim(); $g = if ($i -lt $got.Count) { $got[$i].Trim() } else { "<missing>" }
  # compare on the mnemonic text (3rd tab-field), tolerant of 0x formatting
  $et = ($e -split "`t")[2]; $gt = ($g -split "`t")[2]
  $etn = $et -replace "0x",""; $gtn = $gt -replace "0x",""
  if ($etn -ne $gtn) { Write-Host "FAIL line ${i}: expected [$et] got [$gt]" -ForegroundColor Red; $fail++ }
}
if ($fail -eq 0) { Write-Host "PASS: all $($exp.Count) cases" -ForegroundColor Green }
else { Write-Host "$fail FAILURES" -ForegroundColor Red; exit 1 }
