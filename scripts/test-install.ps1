# SPDX-License-Identifier: Apache-2.0
# Copyright (c) Alingan Patra
#
# Runs every install guide's steps, taken from docs/install/source.json, in a
# clean container and records the outcome in docs/install/tested.json, which
# scripts/gen-install-docs.ps1 prints in each guide. Downloads come from the
# local build/ directory (curl file:///b) unless -Base names a release URL.
#
# Usage: pwsh scripts/test-install.ps1 [-Only debian-12,alpine-3.20] [-Base <url>]
param(
    [string[]]$Only,
    [string]$Base = 'file:///b'
)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)

$source = Get-Content docs/install/source.json -Raw | ConvertFrom-Json
$version = (Select-String -Path Cargo.toml -Pattern '^version = "(.+)"' |
    Select-Object -First 1).Matches[0].Groups[1].Value
$resultsPath = 'docs/install/tested.json'
$results = @{}
if (Test-Path $resultsPath) {
    (Get-Content $resultsPath -Raw | ConvertFrom-Json).PSObject.Properties |
        ForEach-Object { $results[$_.Name] = $_.Value }
}

# The guide's steps as one POSIX shell script. Containers have no init
# system, so the "start" step is replaced by running wedge as the service
# account directly; the units themselves are checked by systemd-analyze.
function New-TestScript($p) {
    $steps = @(
        'set -eu',
        "VERSION=$version",
        "BASE=$Base",
        # In a root container `sudo` is not needed (and often not installed).
        'sudo() { if [ "$(id -u)" = 0 ]; then "$@"; else command sudo "$@"; fi; }',
        'cd /tmp',
        $p.prerequisites,
        "curl -fsSLO `"`$BASE/$($p.asset)`"",
        'curl -fsSLO "$BASE/SHA256SUMS"',
        "grep `" $($p.asset)`$`" SHA256SUMS | sha256sum -c -",
        $p.install,
        'sudo wedge check-config -c /etc/wedge/wedge.toml',
        # Test harness only: a tool to drop to the wedge user (minimal images
        # may lack su), then run the service the way its unit would.
        'command -v setpriv >/dev/null || command -v su >/dev/null || dnf install -y -q util-linux >/dev/null 2>&1 || true',
        'if command -v su >/dev/null; then su -s /bin/sh wedge -c "exec $(command -v wedge) run -c /etc/wedge/wedge.toml" 2>/tmp/wedge.err & else setpriv --reuid=wedge --regid=wedge --clear-groups "$(command -v wedge)" run -c /etc/wedge/wedge.toml 2>/tmp/wedge.err & fi',
        # Wait for wedge to listen (a fixed 1 s sleep was flaky under load).
        'for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do curl -fsS http://127.0.0.1:8080/ 2>/dev/null | grep -qi "<h1>" && break; sleep 0.5; done',
        'curl -fsS http://127.0.0.1:8080/ | grep -qi "<h1>" || { cat /tmp/wedge.err; exit 1; }',
        'kill %1 2>/dev/null || pkill wedge || true',
        'echo "serves its default page as the wedge user"'
    )
    if ($p.kind -in 'deb', 'rpm') {
        $steps += $p.remove.Replace('sudo apt-get remove', 'sudo apt-get remove -y').Replace('sudo dnf remove', 'sudo dnf remove -y')
        $steps += '[ ! -e /usr/bin/wedge ] && echo "removed cleanly"'
    }
    $steps += 'echo GUIDE-PASSED'
    ($steps -join "`n") + "`n"
}

$failed = @()
foreach ($p in $source.platforms) {
    if (-not $p.image) { continue }
    if ($Only -and $p.id -notin $Only) { continue }
    $script = New-TestScript $p
    $file = Join-Path ([IO.Path]::GetTempPath()) "wedge-install-$($p.id).sh"
    [IO.File]::WriteAllText($file, $script)
    docker pull -q $p.image | Out-Null
    $digest = (docker image inspect $p.image --format '{{index .RepoDigests 0}}') 2>$null
    Write-Host "== $($p.id) ($($p.image))"
    $output = docker run --rm -v "${PWD}\build:/b:ro" -v "${file}:/guide.sh:ro" $p.image sh /guide.sh 2>&1
    $passed = ($output -join "`n") -match 'GUIDE-PASSED'
    $output | Select-Object -Last 4 | ForEach-Object { "   $_" }
    $results[$p.id] = [ordered]@{
        result  = if ($passed) { 'passed' } else { 'failed' }
        date    = (Get-Date -Format 'yyyy-MM-dd')
        version = $version
        image   = $digest
    }
    if (-not $passed) { $failed += $p.id }
}

$sorted = [ordered]@{}
foreach ($key in ($results.Keys | Sort-Object)) { $sorted[$key] = $results[$key] }
$sorted | ConvertTo-Json -Depth 4 | Set-Content $resultsPath
if ($failed) { throw "install guide failed on: $($failed -join ', ')" }
Write-Host "all install guides passed"
