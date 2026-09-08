# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# Assembler regression for SPLIT immediates -- operands whose bits are spread across
# both words of a two-word instruction: the 22-bit branch/call/pointer operand
# (LB / LC / LCR / FFC / MOVL XARn,#22bit) and the FPU #16FHi operand
# (MOVIZ / MOVXI / CMPF32 / MAXF32 / MINF32 / ADDF32 / MPYF32 / SUBF32).
#
# These are rejoined in a disassembly action, e.g.
#     [ xar22 = (loc_off6 << 16) | imm16; ]
# and Ghidra's assembler INVERTS that expression to solve for the fields. It can
# invert `|` over disjoint fields; it cannot invert `+`. Since the fields never
# overlap the two are numerically identical, so writing `+` breaks nothing about
# disassembly, emulation or the decompiler and every other test here still passes --
# only "Patch Instruction" and the WildcardAssembler stop working, on the pointer
# loads that are how this target names every peripheral. Hence a dedicated gate.
#
# Everything checked lives in ghidra_scripts\AssembleRoundTrip.java, including the
# expected encodings, so there is one source of truth and this harness only has to
# get Ghidra to run it.
#
# Usage:  pwsh -File tests\run_assembler_check.ps1 [-Ghidra <install-root>]
param(
  [string]$Ghidra = $env:GHIDRA_INSTALL_DIR,
  [string]$Module = (Split-Path -Parent $PSScriptRoot)
)
. "$PSScriptRoot\_env.ps1"
Import-C28xEnv $Module
if (-not $PSBoundParameters.ContainsKey('Ghidra')) { $Ghidra = $env:GHIDRA_INSTALL_DIR }
if (-not $Ghidra) { throw "Set -Ghidra, `$env:GHIDRA_INSTALL_DIR, or .c28x.env to your Ghidra install." }
$ErrorActionPreference = "Stop"
$lang = "$Module\data\languages"
$tmp  = Get-C28xScratchRoot -Module $Module -Kind "asm"

# Compile + install, same as the disassembler regression: this must test the spec in
# the tree, not whatever .sla was installed last.
#
# UNC-safe: sleigh.bat is a cmd script and cmd.exe refuses a UNC working directory,
# silently landing in C:\Windows and failing to find the .slaspec -- so copy to a
# Windows-local build dir and compile there, exactly as run_disasm_test.ps1 does.
# (Ghidra will lazily recompile a stale .sla at load time, which is precisely what
# makes a skipped compile here look like a pass.)
$bld = "$tmp\build"
New-Item -ItemType Directory -Force -Path $bld | Out-Null
Copy-Item "$lang\*" $bld -Force
Push-Location $bld
try {
  $null | & "$Ghidra\support\sleigh.bat" "tms320c28x.slaspec"
  if (-not (Test-Path "$bld\tms320c28x.sla")) { throw "SLEIGH compile failed" }
  Copy-Item "$bld\tms320c28x.sla" $lang -Force
} finally { Pop-Location }
Install-C28xModule -Ghidra $Ghidra -Module $Module | Out-Null

$ws = "$tmp\run"
New-Item -ItemType Directory -Force -Path "$ws\proj", "$ws\scripts" | Out-Null
Copy-Item "$Module\ghidra_scripts\AssembleRoundTrip.java" "$ws\scripts\" -Force

# headless needs SOMETHING to import to get a Program (the assembler reads its
# starting context from one). The script builds its own corpus in a block it
# creates, so this stub is four words of nothing and its content is irrelevant.
[System.IO.File]::WriteAllBytes("$ws\stub.bin", (New-Object byte[] 8))

$raw = & "$Ghidra\support\analyzeHeadless.bat" "$ws\proj" asm `
  -import "$ws\stub.bin" -processor "TMS320C28x:LE:32:default" `
  -scriptPath "$ws\scripts" -postScript AssembleRoundTrip.java `
  -noanalysis -overwrite 2>&1

$out = $raw | ForEach-Object { "$_" } |
  Where-Object { $_ -match 'AssembleRoundTrip\.java> ' } |
  ForEach-Object { ($_ -replace '.*AssembleRoundTrip\.java> ', '') -replace ' \(GhidraScript\)\s*$', '' }

$out | ForEach-Object { Write-Host $_ }

if ($out -match '^ASSEMBLER PASS') { exit 0 }

Write-Host "--- assembler check did not pass; raw analyzeHeadless output follows ---"
$raw | ForEach-Object { Write-Host "$_" }
exit 1
