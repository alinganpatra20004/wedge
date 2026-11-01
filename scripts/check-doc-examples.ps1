# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OpenEdge Labs
#
# Checks every ```toml block in docs/guide/*.md with `wedge check-config`,
# so the user guide never shows a configuration wedge would reject.
#
# Usage: pwsh scripts/check-doc-examples.ps1 [-Wedge path/to/wedge]
param([string]$Wedge)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if (-not $Wedge) {
    cargo build -q -p wedge
    if ($LASTEXITCODE -ne 0) { throw 'build failed' }
    $Wedge = if ($IsWindows) { 'target/debug/wedge.exe' } else { 'target/debug/wedge' }
}

$work = Join-Path ([IO.Path]::GetTempPath()) "wedge-doc-examples-$PID"
New-Item -ItemType Directory -Force $work | Out-Null
$checked = 0
$failures = @()
foreach ($page in Get-ChildItem docs/guide -Filter *.md) {
    $text = (Get-Content $page.FullName -Raw) -replace "`r`n", "`n"
    $blocks = [regex]::Matches($text, '(?ms)^```toml\n(.*?)^```')
    $n = 0
    foreach ($block in $blocks) {
        $n++
        $file = Join-Path $work 'wedge.toml'
        [IO.File]::WriteAllText($file, $block.Groups[1].Value)
        $output = & $Wedge check-config -c $file 2>&1
        $checked++
        if ($LASTEXITCODE -ne 0) {
            $failures += "$($page.Name) example $n`n$($block.Groups[1].Value)`n=> $($output -join "`n")"
        }
    }
}
Remove-Item -Recurse -Force $work
if ($failures) {
    $failures | ForEach-Object { Write-Host "FAILED: $_`n" }
    throw "$($failures.Count) of $checked documentation examples are invalid"
}
Write-Host "all $checked documentation examples pass wedge check-config"
