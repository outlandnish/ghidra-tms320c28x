# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# Per-worktree config loader (PowerShell). PowerShell counterpart of tests/_env.sh
# -- see that file (and docs/WORKTREES.md) for the rationale. Dot-source this, then:
#
#     . "$PSScriptRoot\_env.ps1"
#     Import-C28xEnv $Module
#
# Reads KEY=VALUE lines from `.c28x.env` at the worktree root (gitignored local
# machine config; template: .c28x.env.example). Absent file => no-op.
#
# NOTE on precedence: a script param that defaults to `$env:X` is bound BEFORE the
# body runs, so after Import-C28xEnv the caller must re-resolve any such param from
# $env when it was not passed explicitly, e.g.:
#     if (-not $PSBoundParameters.ContainsKey('Ghidra')) { $Ghidra = $env:GHIDRA_INSTALL_DIR }

function Import-C28xEnv {
  param([Parameter(Mandatory)][string]$Root)
  $f = Join-Path $Root ".c28x.env"
  if (-not (Test-Path -LiteralPath $f)) { return }
  foreach ($line in Get-Content -LiteralPath $f) {   # Get-Content strips CRLF for us
    $t = $line.Trim()
    if ($t -eq "" -or $t.StartsWith("#")) { continue }
    $eq = $t.IndexOf("=")
    if ($eq -lt 1) { continue }
    $k = $t.Substring(0, $eq).Trim()
    $v = $t.Substring($eq + 1)      # keep the value verbatim (paths may contain spaces)
    if ($k -eq "") { continue }
    Set-Item -Path "env:$k" -Value $v
  }
}

# Get-C28xScratchRoot -Module <worktree-root> -Kind <tag>
# A per-worktree scratch dir under $env:TEMP, keyed by the worktree path so two
# worktrees never share scratch (the old fixed "$env:TEMP\c28x-*" collided), yet
# repeated runs of the SAME worktree reuse one dir so nothing leaks.
function Get-C28xScratchRoot {
  param(
    [Parameter(Mandatory)][string]$Module,
    [Parameter(Mandatory)][string]$Kind
  )
  $full = (Resolve-Path -LiteralPath $Module).Path
  $sha  = [Security.Cryptography.SHA1]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($full))
  $hash = -join ($sha[0..3] | ForEach-Object { $_.ToString('x2') })
  $leaf = (Split-Path -Leaf $full) -replace '[^A-Za-z0-9._-]', '_'
  return (Join-Path $env:TEMP ("c28x-{0}-{1}-{2}" -f $leaf, $hash, $Kind))
}

# Install-C28xModule -Ghidra <ghidra-root> -Module <worktree-root>
#
# Copies data/languages/* and Module.manifest into the location Ghidra actually
# loads the C28x module from -- and ONLY that one location.
#
# Precedence: if an installed extension exists under $env:APPDATA\ghidra\...\
# Extensions\ghidra-tms320c28x, patch it. Otherwise fall back to the drop-in
# $Ghidra\Ghidra\Processors\TMS320C28x directory.
#
# Populating BOTH is a bug -- Ghidra 12.1.2 detects duplicate <language> and
# refuses to start with "Language ... previously defined". The extension used to
# silently shadow the drop-in; it doesn't any more.
#
# Returns the path to the "$installedRoot\lib" directory (creating it) so the
# caller can drop a compiled jar in the right place.
function Install-C28xModule {
  param(
    [Parameter(Mandatory)][string]$Ghidra,
    [Parameter(Mandatory)][string]$Module
  )
  $lang = Join-Path $Module "data\languages"
  $manifest = Join-Path $Module "Module.manifest"

  # Prefer an installed extension when present.
  $extRoot = "$env:APPDATA\ghidra"
  $extDir = $null
  if (Test-Path $extRoot) {
    $extDir = Get-ChildItem -Path $extRoot -Filter "ghidra_*" -Directory -ErrorAction SilentlyContinue |
      ForEach-Object { $p = Join-Path $_.FullName "Extensions\ghidra-tms320c28x"; if (Test-Path $p) { $p } } |
      Select-Object -First 1
  }

  if ($extDir) {
    $inst = Join-Path $extDir "data\languages"
    $lib  = Join-Path $extDir "lib"
    New-Item -ItemType Directory -Force -Path $inst,$lib | Out-Null
    Copy-Item "$lang\*" $inst -Force
    Copy-Item $manifest (Join-Path $extDir "Module.manifest") -Force
    Write-Host "installed to extension: $extDir"
    return $lib
  }

  $modroot = "$Ghidra\Ghidra\Processors\TMS320C28x"
  $inst = "$modroot\data\languages"
  $lib  = "$modroot\lib"
  New-Item -ItemType Directory -Force -Path $inst,$lib | Out-Null
  Copy-Item "$lang\*" $inst -Force
  Copy-Item $manifest "$modroot\Module.manifest" -Force
  Write-Host "installed to drop-in: $modroot"
  return $lib
}
