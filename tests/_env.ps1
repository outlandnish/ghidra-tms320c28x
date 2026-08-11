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
