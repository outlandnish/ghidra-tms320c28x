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

$src = "$Module\src\main\java\ghidra\program\emulation\TMS320C28xEmulateInstructionStateModifier.java"
$cp  = ((Get-ChildItem "$Ghidra\Ghidra\Framework" -Filter "*.jar" -Recurse | ForEach-Object { $_.FullName }) -join ';')
# Per-worktree scratch dir (was a fixed "$env:TEMP\c28x-mod-build" that collided across worktrees).
$out = (Join-Path (Get-C28xScratchRoot -Module $Module -Kind "modbuild") "out"); New-Item -ItemType Directory -Force $out | Out-Null

# Ghidra 12.x runs on JDK 21+; --release 21 keeps the class loadable on any supported JVM.
& $javac --release 21 -cp $cp -d $out $src
$cls = "$out\ghidra\program\emulation\TMS320C28xEmulateInstructionStateModifier.class"
if (-not (Test-Path $cls)) { throw "compile failed (no .class)" }

$mod = "$Ghidra\Ghidra\Processors\TMS320C28x"
New-Item -ItemType Directory -Force "$mod\lib" | Out-Null
& $jarTool --create --file "$mod\lib\TMS320C28x.jar" -C $out ghidra
Copy-Item "$Module\data\languages\tms320c28x.pspec" "$mod\data\languages\tms320c28x.pspec" -Force
Write-Host "Installed $mod\lib\TMS320C28x.jar + pspec. RESTART Ghidra to load the RPTB state modifier." -ForegroundColor Green
