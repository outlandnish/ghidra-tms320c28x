# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
# C28x SLEIGH *semantics* regression test (run from PowerShell).
#
# run_disasm_test.ps1 checks the listing; this checks what the p-code actually does, by
# emulating the FPU status-flag instructions and reading the STF sub-registers back.
# It is the only test that can catch a wrong bit order inside a mask -- SETFLG's FLAG
# field is split across both instruction words with the halves in the opposite order
# from the #16FHi immediates, and swapping them moves RND32 onto NI while the
# disassembly still looks entirely plausible.
#
# Assumes the language is already installed (run run_disasm_test.ps1 first).
#
# Usage:  pwsh -File tests\run_emu_test.ps1 -Ghidra <ghidra-install-dir>
param(
  [string]$Ghidra = $env:GHIDRA_INSTALL_DIR,
  [string]$Module = (Split-Path -Parent $PSScriptRoot)
)
if (-not $Ghidra) { throw "Set -Ghidra or the GHIDRA_INSTALL_DIR env var to your Ghidra install." }
$ErrorActionPreference = "Stop"

$ws = "$env:TEMP\c28x-emu"
New-Item -ItemType Directory -Force -Path "$ws\proj","$ws\scripts" | Out-Null
Copy-Item "$Module\ghidra_scripts\EmuFlagTest.java" "$ws\scripts\" -Force
Copy-Item "$Module\tests\fpu_flags.bin" "$ws\" -Force

Push-Location $ws
$raw = & "$Ghidra\support\analyzeHeadless.bat" "$ws\proj" emu `
  -import "$ws\fpu_flags.bin" -processor "TMS320C28x:LE:32:default" `
  -scriptPath "$ws\scripts" -postScript EmuFlagTest.java -noanalysis -overwrite 2>&1
Pop-Location

$raw | Select-String "EmuFlagTest.java> (PASS|FAIL)" | ForEach-Object { $_.ToString() }
if ($raw | Select-String "EmuFlagTest.java> PASS") {
  Write-Host "emulation semantics: OK" -ForegroundColor Green
}
else {
  Write-Host "--- emulation test did not pass; full analyzeHeadless output follows ---" -ForegroundColor Red
  $raw
  exit 1
}
