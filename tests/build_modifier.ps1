# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
# Compile + install the C28x emulation state modifier (RPTB hardware-loop support).
#
# SLEIGH can't model the RPTB zero-overhead block repeat (implicit loop-back at an
# arbitrary block-end instruction). Ghidra's answer is an EmulateInstructionStateModifier
# (same mechanism Hexagon uses for its hardware loops). This compiles that class and drops
# it, plus the pspec that references it, into the installed processor module.
#
# Quick-iteration analogue of run_disasm_test.ps1 (which drops in the .sla). A full
# `gradle buildExtension` also compiles src/main/java into the extension jar for releases.
#
# RESTART Ghidra afterwards -- the classpath and pspec are read at startup.
#
# Usage: pwsh -File tests\build_modifier.ps1 [-Ghidra <dir>] [-Jdk <jdk-home>]
param(
  [string]$Ghidra = $env:GHIDRA_INSTALL_DIR,
  [string]$Jdk    = $null,
  [string]$Module = (Split-Path -Parent $PSScriptRoot)
)
# Load this worktree's local config (.c28x.env), then re-resolve -Ghidra from it
# when not passed explicitly. Absent file => no-op.
. "$PSScriptRoot\_env.ps1"
Import-C28xEnv $Module
if (-not $PSBoundParameters.ContainsKey('Ghidra')) { $Ghidra = $env:GHIDRA_INSTALL_DIR }
if (-not $Ghidra) { $Ghidra = "C:\Users\nisha\Downloads\ghidra_12.1.2_PUBLIC_20260605\ghidra_12.1.2_PUBLIC" }
$ErrorActionPreference = "Stop"

# locate javac / jar
if ($Jdk) { $javac = "$Jdk\bin\javac.exe" }
else { $javac = (Get-Command javac -ErrorAction SilentlyContinue).Source }
if (-not $javac -or -not (Test-Path $javac)) { $javac = "C:\Program Files\Microsoft\jdk-25.0.0.36-hotspot\bin\javac.exe" }
$jarTool = Join-Path (Split-Path $javac) "jar.exe"
if (-not (Test-Path $javac)) { throw "javac not found; pass -Jdk <jdk-home>" }

# Compile EVERY class under src/main/java, not just the state modifier. The jar this
# produces REPLACES whatever jar the target module already has, so a partial build would
# silently drop the analyzers (FFC return, switch, ABI) that ship in the same jar.
$srcs = Get-ChildItem -Path "$Module\src\main\java" -Filter "*.java" -Recurse | ForEach-Object { $_.FullName }
if (-not $srcs) { throw "no sources under $Module\src\main\java" }
# Analyzers extend Features/Base classes, so the classpath needs all of Ghidra, not just Framework.
$cp  = ((Get-ChildItem "$Ghidra\Ghidra" -Filter "*.jar" -Recurse | ForEach-Object { $_.FullName }) -join ';')
# Per-worktree scratch dir (was a fixed "$env:TEMP\c28x-mod-build" that collided across worktrees).
$out = (Join-Path (Get-C28xScratchRoot -Module $Module -Kind "modbuild") "out"); New-Item -ItemType Directory -Force $out | Out-Null
Get-ChildItem $out -Recurse -File -ErrorAction SilentlyContinue | Remove-Item -Force

# Ghidra 12.x runs on JDK 21+; --release 21 keeps the class loadable on any supported JVM.
$srcList = Join-Path (Split-Path $out -Parent) "sources.txt"
$srcs | Set-Content $srcList -Encoding ascii
& $javac --release 21 -nowarn -cp $cp -d $out "@$srcList"
$cls = "$out\ghidra\program\emulation\TMS320C28xEmulateInstructionStateModifier.class"
if (-not (Test-Path $cls)) { throw "compile failed (no .class)" }

# Install the language into the ONE location Ghidra loads the module from, and put the jar
# in the lib/ that call returns -- the jar and the .sla are a matched pair (the current .sla
# expects postExecuteCallback to drive RPT alone), so they must not land in different modules.
$lib = Install-C28xModule -Ghidra $Ghidra -Module $Module

# REPLACE the module's existing jar rather than adding a second one. An extension already
# ships lib\ghidra-tms320c28x.jar containing these same classes; writing a differently-named
# jar beside it puts two copies of every class on the classpath and Ghidra picks by scan
# order, which is exactly the stale-class ambiguity this script exists to resolve.
$existing = Get-ChildItem $lib -Filter "*.jar" -File -ErrorAction SilentlyContinue
$jarPath = if ($existing.Count -eq 1) { $existing[0].FullName } else { Join-Path $lib "TMS320C28x.jar" }
& $jarTool --create --file $jarPath -C $out ghidra

Write-Host "Installed $jarPath ($(($srcs).Count) sources) + languages. RESTART Ghidra to load it." -ForegroundColor Green
