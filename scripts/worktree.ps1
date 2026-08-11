# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
#
# git-worktree helper (PowerShell). PowerShell counterpart of scripts/worktree.sh
# -- wraps `git worktree`, seeds each new worktree's .c28x.env so the dev harnesses
# target the right Ghidra, and warns when two worktrees pin the SAME Ghidra install
# (which cannot run headless tests in parallel; the module is a singleton per
# install). See docs/WORKTREES.md.
#
# Usage:
#   pwsh -File scripts\worktree.ps1 add <branch> [path]
#   pwsh -File scripts\worktree.ps1 list
#   pwsh -File scripts\worktree.ps1 remove <path> [-Force]
#   pwsh -File scripts\worktree.ps1 env [path]
#   pwsh -File scripts\worktree.ps1 help
param(
  [Parameter(Position = 0)][string]$Command = "help",
  [Parameter(Position = 1)][string]$Arg1,
  [Parameter(Position = 2)][string]$Arg2,
  [switch]$Force
)
. "$PSScriptRoot\..\tests\_env.ps1"

function Die($m) { Write-Host "error: $m" -ForegroundColor Red; exit 1 }
function Test-Ref { param([string]$Root, [string]$Ref) & git -C $Root show-ref --verify --quiet $Ref; return ($LASTEXITCODE -eq 0) }
function Invoke-Git { param([string[]]$GitArgs) & git @GitArgs; if ($LASTEXITCODE -ne 0) { Die ("git " + ($GitArgs -join ' ') + " failed ($LASTEXITCODE)") } }

# Absolute path to the MAIN worktree (holding the shared .git), from any worktree.
function Get-MainRoot {
  $common = (& git rev-parse --git-common-dir 2>$null)
  if (-not $common) { Die "not inside a git repository" }
  if (-not [IO.Path]::IsPathRooted($common)) { $common = Join-Path (Get-Location).Path $common }
  return (Resolve-Path (Join-Path $common "..")).Path
}

# Resolve KEY as the harnesses would for a worktree (.c28x.env wins, else ambient),
# without mutating this process's environment.
function Get-EnvValue([string]$Root, [string]$Key) {
  $f = Join-Path $Root ".c28x.env"
  if (Test-Path -LiteralPath $f) {
    foreach ($line in Get-Content -LiteralPath $f) {
      $t = $line.Trim()
      if ($t -eq "" -or $t.StartsWith("#")) { continue }
      $eq = $t.IndexOf("=")
      if ($eq -lt 1) { continue }
      if ($t.Substring(0, $eq).Trim() -eq $Key) { return $t.Substring($eq + 1) }
    }
  }
  return [Environment]::GetEnvironmentVariable($Key)
}

function Get-WorktreeRows {
  $rows = @(); $path = $null; $branch = $null
  foreach ($line in (& git worktree list --porcelain)) {
    if     ($line -like "worktree *") { $path = $line.Substring(9) }
    elseif ($line -like "branch *")   { $branch = $line.Substring(7) -replace '^refs/heads/', '' }
    elseif ($line -eq "detached")     { $branch = "(detached)" }
    elseif ($line -eq "") {
      if ($path) { $rows += [pscustomobject]@{ Path = $path; Branch = ($branch ?? "(detached)"); Ghidra = (Get-EnvValue $path "GHIDRA_INSTALL_DIR") } }
      $path = $null; $branch = $null
    }
  }
  if ($path) { $rows += [pscustomobject]@{ Path = $path; Branch = ($branch ?? "(detached)"); Ghidra = (Get-EnvValue $path "GHIDRA_INSTALL_DIR") } }
  return , $rows
}

function Warn-GhidraCollisions([object[]]$rows) {
  $rows | Where-Object { $_.Ghidra } | Group-Object Ghidra | Where-Object { $_.Count -gt 1 } | ForEach-Object {
    Write-Host ("warning: {0} worktrees share Ghidra install: {1}" -f $_.Count, $_.Name) -ForegroundColor Yellow
    $_.Group | ForEach-Object { Write-Host ("      {0} ({1})" -f $_.Path, $_.Branch) -ForegroundColor Yellow }
    Write-Host "  -> headless tests cannot run in these in parallel (module is a singleton per install)." -ForegroundColor Yellow
    Write-Host "     Point one at a second Ghidra in its .c28x.env." -ForegroundColor Yellow
  }
}

function Seed-Env([string]$Src, [string]$Dst) {
  $f = Join-Path $Dst ".c28x.env"
  if (Test-Path -LiteralPath $f) { Write-Host "  .c28x.env already present -- left as is"; return }
  $srcEnv = Join-Path $Src ".c28x.env"
  if (Test-Path -LiteralPath $srcEnv) {
    Copy-Item -LiteralPath $srcEnv -Destination $f; Write-Host "  seeded .c28x.env (copied from the main worktree)"
  }
  elseif ($env:GHIDRA_INSTALL_DIR) {
    $lines = @("# Seeded by scripts/worktree.ps1 from the environment. Edit for this worktree.",
               "GHIDRA_INSTALL_DIR=$($env:GHIDRA_INSTALL_DIR)")
    if ($env:C2000WARE) { $lines += "C2000WARE=$($env:C2000WARE)" }
    if ($env:JAVA_HOME) { $lines += "JAVA_HOME=$($env:JAVA_HOME)" }
    Set-Content -LiteralPath $f -Value $lines -Encoding ascii
    Write-Host "  seeded .c28x.env from the current environment"
  }
  elseif (Test-Path -LiteralPath (Join-Path $Src ".c28x.env.example")) {
    Copy-Item -LiteralPath (Join-Path $Src ".c28x.env.example") -Destination $f
    Write-Host "  no source config + GHIDRA_INSTALL_DIR unset -- wrote a template; EDIT $f"
  }
  else { Write-Host "  no config available to seed -- create $f by hand (see .c28x.env.example)" }
}

function Cmd-Add([string]$Branch, [string]$Path) {
  if (-not $Branch) { Die "usage: worktree.ps1 add <branch> [path]" }
  $root = Get-MainRoot
  $reponame = Split-Path -Leaf $root
  $sanitized = $Branch -replace '/', '-'
  if (-not $Path) { $Path = Join-Path (Split-Path -Parent $root) (Join-Path "$reponame-worktrees" $sanitized) }
  if (Test-Path -LiteralPath $Path) { Die "target path already exists: $Path" }
  New-Item -ItemType Directory -Force (Split-Path -Parent $Path) | Out-Null

  if (Test-Ref $root "refs/heads/$Branch") {
    Write-Host "checking out existing local branch '$Branch' at $Path"
    Invoke-Git @("-C", $root, "worktree", "add", $Path, $Branch)
  }
  elseif (Test-Ref $root "refs/remotes/origin/$Branch") {
    Write-Host "checking out origin/$Branch (new tracking branch) at $Path"
    Invoke-Git @("-C", $root, "worktree", "add", "--track", "-b", $Branch, $Path, "origin/$Branch")
  }
  else {
    $base = "HEAD"
    if     (Test-Ref $root "refs/remotes/origin/main") { $base = "origin/main" }
    elseif (Test-Ref $root "refs/heads/main")          { $base = "main" }
    Write-Host "creating new branch '$Branch' off $base at $Path"
    Invoke-Git @("-C", $root, "worktree", "add", "-b", $Branch, $Path, $base)
  }

  Seed-Env $root $Path
  Write-Host ""
  Write-Host "Done. Next:"
  Write-Host "  cd `"$Path`""
  Write-Host "  pwsh -File scripts\worktree.ps1 env      # confirm this worktree's resolved config"
  Write-Host ""
  Warn-GhidraCollisions (Get-WorktreeRows)
}

function Cmd-List {
  $rows = Get-WorktreeRows
  ("{0,-52}  {1,-28}  {2}" -f "WORKTREE", "BRANCH", "GHIDRA_INSTALL_DIR") | Write-Host
  foreach ($r in $rows) {
    $g = if ($r.Ghidra) { $r.Ghidra } else { "<unset>" }
    ("{0,-52}  {1,-28}  {2}" -f $r.Path, $r.Branch, $g) | Write-Host
  }
  Write-Host ""
  Warn-GhidraCollisions $rows
}

function Cmd-Remove([string]$Path) {
  if (-not $Path) { Die "usage: worktree.ps1 remove <path> [-Force]" }
  $a = @("worktree", "remove", $Path); if ($Force) { $a += "--force" }
  Invoke-Git $a
  Write-Host "removed worktree: $Path  (its branch still exists; delete with: git branch -d <branch>)"
}

function Cmd-Env([string]$Path) {
  if (-not $Path) { $Path = (& git rev-parse --show-toplevel); if ($LASTEXITCODE -ne 0) { Die "not inside a git repository" } }
  $Path = (Resolve-Path -LiteralPath $Path).Path
  Write-Host "worktree: $Path"
  $cfg = Join-Path $Path ".c28x.env"
  if (Test-Path -LiteralPath $cfg) { Write-Host "config:   $cfg" } else { Write-Host "config:   (no .c28x.env -- values below are from the ambient environment)" }
  foreach ($k in @("GHIDRA_INSTALL_DIR", "C2000WARE", "JAVA_HOME")) {
    ("  {0,-20} {1}" -f $k, (Get-EnvValue $Path $k)) | Write-Host
  }
}

switch ($Command) {
  "add"    { Cmd-Add $Arg1 $Arg2 }
  "list"   { Cmd-List }
  "remove" { Cmd-Remove $Arg1 }
  "env"    { Cmd-Env $Arg1 }
  default {
    Write-Host @"
git-worktree helper for ghidra-tms320c28x. See docs/WORKTREES.md.

  add <branch> [path]   create/checkout a worktree + seed its .c28x.env
  list                  list worktrees + their pinned GHIDRA_INSTALL_DIR
  remove <path> [-Force]  git worktree remove <path>
  env [path]            print resolved config for a worktree (default: cwd)
  help
"@
  }
}
