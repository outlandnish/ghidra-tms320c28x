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
#   fpu_parallel -- every parallel ("||") FPU form. These pack five register
#                   selectors plus a mem32 loc byte across both words, and TWO of
#                   the selectors straddle the word boundary in OPPOSITE bit
#                   orders (ReH = e:ee, RfH = ff:f), which is exactly the kind of
#                   thing that decodes plausibly while naming the wrong register.
#                   Assembled by asm2000 from the TI mnemonics, so the expected
#                   registers are TI's, not ours.
#   fpu_flags    -- SETFLG / SAVE / RESTORE. Their 11-bit FLAG mask is split across
#                   both words with the HIGH 6 bits in the LSW and the low 5 in the
#                   MSW -- the opposite order from the #16FHi immediates, and getting
#                   it backwards silently moves RND32 onto NI. Assembled by asm2000
#                   from TI mnemonics (`SETFLG RNDF32=1` -> e610 0200).
#
# Usage:  pwsh -File tests\run_disasm_test.ps1 -Ghidra <ghidra-install-dir>
#   (Ghidra defaults to $env:GHIDRA_INSTALL_DIR; Module defaults to this repo root.)
param(
  [string]$Ghidra = $env:GHIDRA_INSTALL_DIR,
  [string]$Module = (Split-Path -Parent $PSScriptRoot),
  [string[]]$Cases = @("addr_modes", "fpu_display", "fpu_parallel", "fpu_flags")
)
# Load this worktree's local config (.c28x.env), then re-resolve -Ghidra from it
# when it was not passed explicitly. Absent file => no-op (CI is unaffected).
. "$PSScriptRoot\_env.ps1"
Import-C28xEnv $Module
if (-not $PSBoundParameters.ContainsKey('Ghidra')) { $Ghidra = $env:GHIDRA_INSTALL_DIR }
if (-not $Ghidra) { throw "Set -Ghidra, `$env:GHIDRA_INSTALL_DIR, or .c28x.env to your Ghidra install." }
$ErrorActionPreference = "Stop"
$lang = "$Module\data\languages"
# Per-worktree scratch dir (was a fixed "$env:TEMP\c28x-test" that collided across worktrees).
$tmp  = Get-C28xScratchRoot -Module $Module -Kind "test"

# 1. compile (UNC-safe: copy to a Windows-local dir, the .bat can't run from UNC cwd)
$bld = "$tmp\build"; New-Item -ItemType Directory -Force -Path $bld | Out-Null
Copy-Item "$lang\*" $bld -Force
Push-Location $bld
$null | & "$Ghidra\support\sleigh.bat" tms320c28x.slaspec
Pop-Location
if (-not (Test-Path "$bld\tms320c28x.sla")) { throw "SLEIGH compile failed (no .sla)" }
Copy-Item "$bld\tms320c28x.sla" $lang -Force

# 2. reinstall into Ghidra (Module.manifest too, so a fresh Ghidra recognizes the
# directory as a module and discovers the language). Install-C28xModule prefers
# the installed extension when present and falls back to the drop-in Processors
# dir when not -- populating both trips Ghidra 12.1.2's dup-language check.
Install-C28xModule -Ghidra $Ghidra -Module $Module | Out-Null

$ws = "$tmp\run"; New-Item -ItemType Directory -Force -Path "$ws\proj","$ws\scripts" | Out-Null
Copy-Item "$Module\ghidra_scripts\DumpDisasm.java" "$ws\scripts\DumpDisasm.java" -Force

$fail = 0
$total = 0
foreach ($name in $Cases) {
  Write-Host "=== $name ==="

  # 3. headless disassemble
  Copy-Item "$Module\tests\$name.bin" "$ws\$name.bin" -Force
  Push-Location $ws
  # JDK 25 emits sun.misc.Unsafe deprecation warnings on stderr which trip
  # `$ErrorActionPreference = Stop`; loosen it around the native invocation.
  $prevEA = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    $raw = & "$Ghidra\support\analyzeHeadless.bat" "$ws\proj" "t_$name" `
      -import "$ws\$name.bin" -processor "TMS320C28x:LE:32:default" `
      -scriptPath "$ws\scripts" -postScript DumpDisasm.java -noanalysis -overwrite 2>&1
  } finally {
    $ErrorActionPreference = $prevEA
    Pop-Location
  }

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
