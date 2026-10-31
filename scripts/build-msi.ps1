# SPDX-License-Identifier: Apache-2.0
# Copyright (c) Alingan Patra
#
# Builds the Windows installer build/wedge-<version>-x86_64.msi from the
# layout in build/x86_64-pc-windows-msvc (made by scripts/build-all.ps1).
# Needs the .NET SDK; installs the WiX 5 command-line tool if missing.
#
# Usage: pwsh scripts/build-msi.ps1
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)

$wixVersion = '5.0.2'
$version = (Select-String -Path Cargo.toml -Pattern '^version = "(.+)"' |
    Select-Object -First 1).Matches[0].Groups[1].Value
$layout = 'build/x86_64-pc-windows-msvc'
if (-not (Test-Path "$layout/wedge.exe")) { throw "missing $layout/wedge.exe; run scripts/build-all.ps1 first" }

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    dotnet tool install --global wix --version $wixVersion
    $env:PATH += [IO.Path]::PathSeparator + (Join-Path $HOME '.dotnet/tools')
}
foreach ($ext in @('WixToolset.UI.wixext')) {
    wix extension add -g "$ext/$wixVersion" | Out-Null
}

# The license dialog needs RTF; convert LICENSE (plain text) to it.
$rtf = 'build/license.rtf'
$escaped = (Get-Content LICENSE -Raw).Replace('\', '\\').Replace('{', '\{').Replace('}', '\}') -replace "`r?`n", "\par`n"
[IO.File]::WriteAllText((Join-Path $PWD $rtf), "{\rtf1\ansi\deff0{\fonttbl{\f0 Consolas;}}\fs16 $escaped}")

$msi = "build/wedge-$version-x86_64.msi"
# Absolute paths: WiX resolves <Files> globs relative to the .wxs file.
function Get-Full([string]$path) { (Resolve-Path $path).Path }
wix build packaging/windows/wedge.wxs -arch x64 `
    -ext WixToolset.UI.wixext `
    -d "Version=$version" -d "BuildDir=$(Get-Full $layout)" `
    -d "BrandDir=$(Get-Full packaging/branding/generated)" -d "LicenseRtf=$(Get-Full $rtf)" `
    -d "ConfigFile=$(Get-Full packaging/windows/wedge.toml)" `
    -d "TestPage=$(Get-Full packaging/linux/www/index.html)" `
    -o $msi
if ($LASTEXITCODE -ne 0) { throw 'wix build failed' }
Remove-Item $rtf
Get-Item $msi | Format-Table Name, Length -AutoSize
