# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# SPRU applied-signature regression test (PowerShell mirror of
# run_abi_applied_check.sh) -- end-to-end analyzer probe.
#
# Complements run_abi_check (cspec via PrototypeModel) and run_abi_analyzer_check
# (pure allocator). This harness is the only one that exercises
# ApplyFunctionSignatureCmd -> Function.updateFunction -> TMS320C28xAbiAnalyzer,
# which is the only path that can test:
#   - varargs (setVarArgs(true) round-trips into fn.hasVarArgs(), analyzer
#     forces the last named arg to the stack per SPRU §7.3.1);
#   - hidden struct-return pointer (cspec's <pentry storage="hiddenret"> is
#     only consulted by real function-analysis, not by getStorageLocations).
#
# Auto-analysis IS enabled (unlike the earlier two harnesses) so functions
# materialize from ELF symbols first; the analyzer is then invoked EXPLICITLY
# from DumpAppliedProtos.java so the output is deterministic.
#
# Usage:  pwsh -File tests\run_abi_applied_check.ps1 [-Ghidra <dir>] [-Update]
#
# NOTE: rebuilds ghidra-tms320c28x.jar with ALL analyzer + modifier classes.
# Running build_modifier.ps1 afterwards overwrites with just the modifier
# (same last-runner-wins pattern as .sla installs).
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

# locate javac / jar
$javac = $null; $jartool = $null
if ($env:JAVA_HOME) {
    $javac   = Join-Path $env:JAVA_HOME "bin\javac.exe"
    $jartool = Join-Path $env:JAVA_HOME "bin\jar.exe"
} else {
    $javac   = (Get-Command javac.exe -ErrorAction SilentlyContinue).Source
    $jartool = (Get-Command jar.exe   -ErrorAction SilentlyContinue).Source
}
if (-not $javac -or -not (Test-Path $javac)) { throw "javac not found (set `$env:JAVA_HOME or put JDK on PATH)" }
if (-not $jartool -or -not (Test-Path $jartool)) { throw "jar not found (set `$env:JAVA_HOME or put JDK on PATH)" }

$lang = "$Module\data\languages"
$tmp  = Get-C28xScratchRoot -Module $Module -Kind "abiapplied"

# 1. Compile the .sla in a Windows-local dir (sleigh.bat can't run from UNC cwd).
$bld = "$tmp\build"; New-Item -ItemType Directory -Force -Path $bld | Out-Null
Copy-Item "$lang\*" $bld -Force
Push-Location $bld
$null | & "$Ghidra\support\sleigh.bat" tms320c28x.slaspec
Pop-Location
if (-not (Test-Path "$bld\tms320c28x.sla")) { throw "SLEIGH compile failed" }
Copy-Item "$bld\tms320c28x.sla" $lang -Force

# 2. Install cspec + sla + Module.manifest; returns lib/ dir for the jar.
$libDir = Install-C28xModule -Ghidra $Ghidra -Module $Module

# 3. Compile ALL src/main/java classes and bundle into the extension jar.
$cpParts = @()
foreach ($sub in @("Framework","Features","Processors")) {
    Get-ChildItem -Path "$Ghidra\Ghidra\$sub" -Recurse -Filter *.jar -ErrorAction SilentlyContinue |
        ForEach-Object { $cpParts += $_.FullName }
}
$cp = $cpParts -join ";"

$srcDir = "$Module\src\main\java"
$srcs = Get-ChildItem -Path $srcDir -Recurse -Filter *.java | ForEach-Object { $_.FullName }
$classes = "$tmp\classes"
New-Item -ItemType Directory -Force -Path $classes | Out-Null
& $javac --release 21 -cp $cp -d $classes @srcs
if ($LASTEXITCODE -ne 0) { throw "javac failed" }

$jarOut = Join-Path $libDir "ghidra-tms320c28x.jar"
& $jartool --create --file $jarOut -C $classes ghidra
if ($LASTEXITCODE -ne 0) { throw "jar failed" }

# 4. Run the applied-signature probe. Analysis IS enabled here (unlike the
# earlier harnesses) so ELF function symbols get turned into Function objects
# before the postScript applies signatures against them.
$ws = "$tmp\run"
New-Item -ItemType Directory -Force -Path "$ws\proj","$ws\scripts" | Out-Null
Copy-Item "$Module\ghidra_scripts\DumpAppliedProtos.java" "$ws\scripts\DumpAppliedProtos.java" -Force

$obj = "$ws\abi_probe.obj"
Copy-Item "$Module\tests\fixtures\abi_probe.obj" $obj -Force

Push-Location $ws
# JDK 25 sun.misc.Unsafe deprecation warnings go to stderr and trip Stop.
$prevEA = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    $raw = & "$Ghidra\support\analyzeHeadless.bat" "$ws\proj" "abi_applied" `
        -import $obj -processor "TMS320C28x:LE:32:default" `
        -scriptPath "$ws\scripts" -postScript DumpAppliedProtos.java `
        -analysisTimeoutPerFile 300 -overwrite 2>&1
} finally {
    $ErrorActionPreference = $prevEA
    Pop-Location
}

if ($env:C28X_ABI_DEBUG) {
    Write-Host "--- raw analyzeHeadless output ($($raw.Count) lines) ---"
    $raw | ForEach-Object { Write-Host $_ }
    Write-Host "--- end raw ---"
}

# Extract block between sentinels, strip script prefix.
$inBlock = $false
$got = @()
foreach ($ln in $raw) {
    $s = "$ln"
    if ($s -match "=== DUMPAPPLIEDPROTOS ===") { $inBlock = $true; continue }
    if ($s -match "=== END ===")               { $inBlock = $false; continue }
    if ($inBlock -and ($s -match "DumpAppliedProtos\.java> ")) {
        $got += ($s -replace ".*DumpAppliedProtos\.java> ", "" -replace " \(GhidraScript\)\s*$","")
    }
}

$expected = "$Module\tests\abi_applied.expected.txt"

if ($Update) {
    [System.IO.File]::WriteAllText($expected,
        (($got -join "`n") + "`n"),
        (New-Object System.Text.UTF8Encoding $false))
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
