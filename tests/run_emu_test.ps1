# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
# C28x SLEIGH *semantics* regression tests (run from PowerShell).
#
# run_disasm_test.ps1 checks the listing; these check what the p-code actually does, by
# emulating and reading registers back. Two suites:
#
#   EmuFlagTest     -- SETFLG / SAVE / RESTORE against the STF sub-registers. The only
#                      test that can catch a wrong bit order INSIDE a mask: SETFLG's FLAG
#                      field is split across both instruction words with the halves in the
#                      opposite order from the #16FHi immediates, and swapping them moves
#                      RND32 onto NI while the disassembly still looks entirely plausible.
#
#   EmuFpuCondTest  -- the TMU_COND_OPERAND / FPU_MINMAX_FLUSH conditioning intrinsics.
#                      These are pcodeops, so their behaviour lives in the compiled
#                      TMS320C28xEmulateInstructionStateModifier and nothing else can see
#                      it. Requires the modifier jar, so build_modifier must have run.
#
# Prerequisites, in order:
#   tests\run_disasm_test.ps1  -- compiles and installs the language
#   tests\build_modifier.ps1   -- compiles and installs the modifier jar
#
# Usage:  pwsh -File tests\run_emu_test.ps1 -Ghidra <ghidra-install-dir>
param(
  [string]$Ghidra = $env:GHIDRA_INSTALL_DIR,
  [string]$Module = (Split-Path -Parent $PSScriptRoot)
)
# Load this worktree's local config (.c28x.env), then re-resolve -Ghidra from it
# when it was not passed explicitly. Absent file => no-op (CI is unaffected).
. "$PSScriptRoot\_env.ps1"
Import-C28xEnv $Module
if (-not $PSBoundParameters.ContainsKey('Ghidra')) { $Ghidra = $env:GHIDRA_INSTALL_DIR }
if (-not $Ghidra) { throw "Set -Ghidra, `$env:GHIDRA_INSTALL_DIR, or .c28x.env to your Ghidra install." }
$ErrorActionPreference = "Stop"

# Per-worktree scratch dir, so parallel worktrees do not collide.
$ws = Get-C28xScratchRoot -Module $Module -Kind "emu"
New-Item -ItemType Directory -Force -Path "$ws\proj","$ws\scripts" | Out-Null
Copy-Item "$Module\ghidra_scripts\EmuFlagTest.java" "$ws\scripts\" -Force
Copy-Item "$Module\ghidra_scripts\EmuFpuCondTest.java" "$ws\scripts\" -Force
Copy-Item "$Module\tests\fpu_flags.bin" "$ws\" -Force
Copy-Item "$Module\tests\fpu_cond.bin" "$ws\" -Force

$fail = 0
function Invoke-Suite([string]$Script, [string]$Fixture) {
  Write-Host "=== $Script ==="
  Push-Location $ws
  $raw = & "$Ghidra\support\analyzeHeadless.bat" "$ws\proj" "e_$Script" `
    -import "$ws\$Fixture" -processor "TMS320C28x:LE:32:default" `
    -scriptPath "$ws\scripts" -postScript "$Script.java" -noanalysis -overwrite 2>&1
  Pop-Location
  $raw | Select-String "$Script.java> (PASS|FAIL)" | ForEach-Object { $_.ToString() }
  if (-not ($raw | Select-String "$Script.java> PASS")) {
    Write-Host "--- $Script did not pass; full analyzeHeadless output follows ---" -ForegroundColor Red
    $raw
    $script:fail = 1
  }
}

Invoke-Suite "EmuFlagTest" "fpu_flags.bin"
Invoke-Suite "EmuFpuCondTest" "fpu_cond.bin"

if ($fail -eq 0) { Write-Host "emulation semantics: OK" -ForegroundColor Green }
else { exit 1 }
