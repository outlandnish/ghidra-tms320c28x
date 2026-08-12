# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# SPRU class-priority allocator regression test (PowerShell mirror of
# run_abi_analyzer_check.sh).
#
# The cspec's declaration-order pentry model can't express SPRU514 §7.3.1's
# cross-class reservation (a later `long` pre-reserves ACC and evicts earlier
# `int` args from AL/AH). TMS320C28xAbiAllocator implements the class-priority
# algorithm; TMS320C28xAbiAnalyzer installs it via CUSTOM_STORAGE on real
# functions.
#
# This harness exercises the ALLOCATOR directly, in parallel to how
# run_abi_check.ps1 probes the cspec. It compiles the module's Java tree
# (analyzers + modifier), drops the resulting ghidra-tms320c28x.jar into the
# installed module's lib/ (extension in $env:APPDATA\ghidra when present,
# otherwise the drop-in Processors dir) alongside the fresh .sla, then runs
# DumpAbiAnalyzer.java which invokes TMS320C28xAbiAllocator.computeParamStorage
# for each probe signature.
#
# Usage:  pwsh -File tests\run_abi_analyzer_check.ps1 [-Ghidra <dir>] [-Update]
#
# NOTE: rebuilds ghidra-tms320c28x.jar with ALL analyzer + modifier classes.
# Running build_modifier.ps1 afterwards will overwrite it with just the modifier
# (its `jar --create` replaces the file). Same last-runner-wins pattern as .sla
# installs.
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
$tmp  = Get-C28xScratchRoot -Module $Module -Kind "abianalyzer"

# 1. Compile the .sla in a Windows-local dir (sleigh.bat can't run from UNC cwd).
$bld = "$tmp\build"; New-Item -ItemType Directory -Force -Path $bld | Out-Null
Copy-Item "$lang\*" $bld -Force
Push-Location $bld
$null | & "$Ghidra\support\sleigh.bat" tms320c28x.slaspec
Pop-Location
if (-not (Test-Path "$bld\tms320c28x.sla")) { throw "SLEIGH compile failed" }
Copy-Item "$bld\tms320c28x.sla" $lang -Force

# 2. Install cspec + sla + Module.manifest. Install-C28xModule picks the
# installed extension when present, else the drop-in Processors dir --
# populating both trips Ghidra's dup-language check. Returns the lib/ dir
# where the compiled jar should go.
$libDir = Install-C28xModule -Ghidra $Ghidra -Module $Module

# 3. Compile ALL src/main/java classes and bundle into the extension jar
# (gradle's naming convention: ghidra-tms320c28x.jar, so a subsequent
# `gradle buildExtension` won't leave a stale duplicate next to ours).
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

# 4. Run the allocator probe via DumpAbiAnalyzer.java.
$ws = "$tmp\run"
New-Item -ItemType Directory -Force -Path "$ws\proj","$ws\scripts" | Out-Null
Copy-Item "$Module\ghidra_scripts\DumpAbiAnalyzer.java" "$ws\scripts\DumpAbiAnalyzer.java" -Force

$obj = "$ws\abi_probe.obj"
Copy-Item "$Module\tests\fixtures\abi_probe.obj" $obj -Force

Push-Location $ws
# JDK 25 emits sun.misc.Unsafe deprecation warnings to stderr which trip
# `$ErrorActionPreference = Stop`; loosen it around the native invocation.
$prevEA = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    $raw = & "$Ghidra\support\analyzeHeadless.bat" "$ws\proj" "abi_analyzer" `
        -import $obj -processor "TMS320C28x:LE:32:default" `
        -scriptPath "$ws\scripts" -postScript DumpAbiAnalyzer.java -noanalysis -overwrite 2>&1
} finally {
    $ErrorActionPreference = $prevEA
    Pop-Location
}

if ($env:C28X_ABI_DEBUG) {
    Write-Host "--- raw analyzeHeadless output ($($raw.Count) lines) ---"
    $raw | ForEach-Object { Write-Host $_ }
    Write-Host "--- end raw ---"
}

# Extract block between DUMPABIANALYZER sentinels, strip script prefix.
$inBlock = $false
$got = @()
foreach ($ln in $raw) {
    $s = "$ln"
    if ($s -match "=== DUMPABIANALYZER ===") { $inBlock = $true; continue }
    if ($s -match "=== END ===")             { $inBlock = $false; continue }
    if ($inBlock -and ($s -match "DumpAbiAnalyzer\.java> ")) {
        $got += ($s -replace ".*DumpAbiAnalyzer\.java> ", "" -replace " \(GhidraScript\)\s*$","")
    }
}

$expected = "$Module\tests\abi_analyzer.expected.txt"

if ($Update) {
    # Write LF-terminated UTF-8 without BOM (matches abi_probe.expected.txt).
    # Set-Content -Encoding UTF8 emits a BOM under Windows PowerShell 5.1.
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
