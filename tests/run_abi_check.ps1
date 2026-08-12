# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# C28x calling-convention regression test (run from PowerShell).
#
# The fixture .obj was compiled once with ti-cgt-c2000 (cl2000.exe) at
#   --abi=eabi --float_support=fpu32 --opt_level=0 --symdebug:none
# and checked in. This harness:
#   1. Recompiles the .sla (UNC-safe copy-to-Windows-local-dir dance).
#   2. Reinstalls the module into $Ghidra so cspec edits take effect --
#      Ghidra caches the compiled spec at startup.
#   3. Headless-imports tests/fixtures/abi_probe.obj as a TMS320C28x program.
#   4. Runs DumpProtos.java, which calls PrototypeModel.getStorageLocations()
#      for each ABI probe signature. That is a direct test of the .cspec, not
#      of Ghidra's body-analysis heuristics -- register-liveness inference
#      would only obscure whether the storage rules themselves are right.
#   5. Diffs the emitted lines against tests/abi_probe.expected.txt.
#
# The expected file records the SPRU514 / SPRAC71 truth. To regenerate after a
# deliberate cspec change, run with -Update.
#
# Usage:  pwsh -File tests\run_abi_check.ps1 [-Ghidra <ghidra-install-dir>] [-Update]
param(
  [string]$Ghidra = $env:GHIDRA_INSTALL_DIR,
  [string]$Module = (Split-Path -Parent $PSScriptRoot),
  [switch]$Update
)
. "$PSScriptRoot\_env.ps1"
Import-C28xEnv $Module
if (-not $PSBoundParameters.ContainsKey('Ghidra')) { $Ghidra = $env:GHIDRA_INSTALL_DIR }
if (-not $Ghidra) { throw "Set -Ghidra, `$env:GHIDRA_INSTALL_DIR, or .c28x.env to your Ghidra install." }
$ErrorActionPreference = "Stop"

$lang = "$Module\data\languages"
$tmp  = Get-C28xScratchRoot -Module $Module -Kind "abi"

# 1. compile .sla in a Windows-local dir (sleigh.bat can't run from a \\wsl.localhost UNC cwd)
$bld = "$tmp\build"; New-Item -ItemType Directory -Force -Path $bld | Out-Null
Copy-Item "$lang\*" $bld -Force
Push-Location $bld
$null | & "$Ghidra\support\sleigh.bat" tms320c28x.slaspec
Pop-Location
if (-not (Test-Path "$bld\tms320c28x.sla")) { throw "SLEIGH compile failed (no .sla)" }
Copy-Item "$bld\tms320c28x.sla" $lang -Force

# 2. install into Ghidra. Copy to BOTH the drop-in Processors dir AND any
# previously-installed extension in $env:APPDATA\ghidra -- the extension
# shadows the drop-in install, so a stale extension will silently mask cspec
# edits and this harness will run against the wrong spec. Discovered the hard
# way while debugging this test.
$modroot = "$Ghidra\Ghidra\Processors\TMS320C28x"
$inst = "$modroot\data\languages"
New-Item -ItemType Directory -Force -Path $inst | Out-Null
Copy-Item "$lang\*" $inst -Force
Copy-Item "$Module\Module.manifest" "$modroot\Module.manifest" -Force

$extRoot = "$env:APPDATA\ghidra"
$extInst = Get-ChildItem -Path $extRoot -Filter "ghidra_*" -Directory -ErrorAction SilentlyContinue |
    ForEach-Object { Get-ChildItem -Path "$($_.FullName)\Extensions\ghidra-tms320c28x\data\languages" -ErrorAction SilentlyContinue |
        Select-Object -First 1 | ForEach-Object { $_.Directory.FullName } } |
    Select-Object -First 1
if ($extInst) {
    Write-Host "also patching extension install at $extInst"
    Copy-Item "$lang\*" $extInst -Force -ErrorAction SilentlyContinue
}

# 3. import + 4. dump prototypes
$ws = "$tmp\run"
New-Item -ItemType Directory -Force -Path "$ws\proj","$ws\scripts" | Out-Null
Copy-Item "$Module\ghidra_scripts\DumpProtos.java" "$ws\scripts\DumpProtos.java" -Force

$obj = "$ws\abi_probe.obj"
Copy-Item "$Module\tests\fixtures\abi_probe.obj" $obj -Force

Push-Location $ws
$raw = & "$Ghidra\support\analyzeHeadless.bat" "$ws\proj" "abi_probe" `
    -import $obj -processor "TMS320C28x:LE:32:default" `
    -scriptPath "$ws\scripts" -postScript DumpProtos.java -noanalysis -overwrite 2>&1
Pop-Location

if ($env:C28X_ABI_DEBUG) {
    Write-Host "--- raw analyzeHeadless output ($($raw.Count) lines) ---"
    $raw | ForEach-Object { Write-Host $_ }
    Write-Host "--- end raw ---"
}

# Extract the block between the DUMPPROTOS sentinels. Only keep lines that came
# from DumpProtos itself (they carry the "DumpProtos.java> " prefix) -- Ghidra
# interleaves INFO / WARN lines from other components into the same stream, and
# without this filter the very first INFO log bleeds into the first probe row.
$inBlock = $false
$got = @()
foreach ($ln in $raw) {
    $s = "$ln"
    if ($s -match "=== DUMPPROTOS ===") { $inBlock = $true; continue }
    if ($s -match "=== END ===")        { $inBlock = $false; continue }
    if ($inBlock -and ($s -match "DumpProtos\.java> ")) {
        $got += ($s -replace ".*DumpProtos\.java> ", "" -replace " \(GhidraScript\)\s*$","")
    }
}

$expected = "$Module\tests\abi_probe.expected.txt"

if ($Update) {
    Set-Content -Path $expected -Value $got -Encoding UTF8
    Write-Host "wrote $expected ($($got.Count) lines)"
    exit 0
}

if (-not (Test-Path $expected)) {
    Write-Host "no expected file yet; re-run with -Update to seed it. actual output:" -ForegroundColor Yellow
    $got | ForEach-Object { Write-Host $_ }
    exit 2
}

$exp = Get-Content $expected
$fail = 0
for ($i = 0; $i -lt [Math]::Max($exp.Count, $got.Count); $i++) {
    $e = if ($i -lt $exp.Count) { $exp[$i] } else { "<missing expected>" }
    $g = if ($i -lt $got.Count) { $got[$i] } else { "<missing actual>" }
    if ($e -ne $g) {
        Write-Host "FAIL line ${i}:" -ForegroundColor Red
        Write-Host "  expected: $e"
        Write-Host "  actual  : $g"
        $fail++
    }
}
if ($fail -eq 0) { Write-Host "PASS: $($exp.Count) lines match" -ForegroundColor Green }
else { Write-Host "$fail FAILURES" -ForegroundColor Red; exit 1 }
