# SPDX-License-Identifier: Apache-2.0
# Copyright (c) Alingan Patra
#
# Builds release binaries for every target this host can produce and lays
# them out in build/:
#
#   build/<target>/            binary, LICENSE, NOTICE, README.md, examples/,
#                              docs/ (user guide, when present), systemd unit
#   build/wedge-<version>-<target>.tar.gz   (Linux) or .zip (Windows)
#   build/SHA256SUMS           checksums of every archive and binary
#
# Windows builds natively; the four Linux targets build in the
# cargo-zigbuild container (needs Docker). macOS binaries are built by the
# release workflow on macOS runners. build/ is not tracked by git.
#
# Usage: pwsh scripts/build-all.ps1 [-SkipLinux] [-SkipWindows] [-ChecksumsOnly]
# -ChecksumsOnly rewrites build/SHA256SUMS for every file now in build/
# (run it after scripts/package-linux.sh and scripts/build-oci.sh).
# -MacOS builds the two macOS targets instead (run it on a Mac; the release
# workflow does this on a macOS runner).
param(
    [switch]$SkipLinux,
    [switch]$SkipWindows,
    [switch]$ChecksumsOnly,
    [switch]$MacOS
)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)

$zigImage = 'ghcr.io/rust-cross/cargo-zigbuild:0.20.1'
$linuxTargets = @(
    'x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu',
    'x86_64-unknown-linux-musl', 'aarch64-unknown-linux-musl'
)
$windowsTarget = 'x86_64-pc-windows-msvc'
$version = (Select-String -Path Cargo.toml -Pattern '^version = "(.+)"' |
    Select-Object -First 1).Matches[0].Groups[1].Value

function Invoke-Checked([scriptblock]$Block, [string]$What) {
    & $Block
    if ($LASTEXITCODE -ne 0) { throw "$What failed (exit $LASTEXITCODE)" }
}

# Copies the binary and the shipped documents into build/<target>/.
function New-Layout([string]$Target, [string]$Binary) {
    $dir = Join-Path build $Target
    if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
    New-Item -ItemType Directory -Force $dir | Out-Null
    Copy-Item $Binary $dir
    Copy-Item LICENSE, NOTICE, README.md $dir
    Copy-Item -Recurse examples (Join-Path $dir 'examples')
    if (Test-Path docs/guide) { Copy-Item -Recurse docs/guide (Join-Path $dir 'docs') }
    if ($Target -like '*linux*') {
        Copy-Item packaging/systemd/wedge.service $dir
    }
    return $dir
}

New-Item -ItemType Directory -Force build | Out-Null
$layouts = @()
if ($ChecksumsOnly -or $MacOS) { $SkipWindows = $true; $SkipLinux = $true }

if ($MacOS) {
    $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $HOME '.cargo' }
    $env:RUSTFLAGS = "--remap-path-prefix=$PWD=/build/wedge --remap-path-prefix=$cargoHome=/cargo"
    foreach ($target in 'aarch64-apple-darwin', 'x86_64-apple-darwin') {
        Write-Host "== $target"
        Invoke-Checked { rustup target add $target } "rustup target add $target"
        Invoke-Checked { cargo build --release --locked -p wedge --target $target } "$target build"
        $layouts += New-Layout $target "target/$target/release/wedge"
    }
    Remove-Item Env:RUSTFLAGS
}

if (-not $SkipWindows) {
    Write-Host "== $windowsTarget"
    # Keep build-machine paths out of the binary (threat model T6.8).
    $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $HOME '.cargo' }
    $env:RUSTFLAGS = "--remap-path-prefix=$PWD=/build/wedge --remap-path-prefix=$cargoHome=/cargo"
    Invoke-Checked { cargo build --release --locked -p wedge --target $windowsTarget } 'Windows build'
    Remove-Item Env:RUSTFLAGS
    $layouts += New-Layout $windowsTarget "target/$windowsTarget/release/wedge.exe"
}

if (-not $SkipLinux) {
    Write-Host "== Linux targets in $zigImage"
    Invoke-Checked {
        docker run --rm -v "${PWD}:/src" -v wedge-zig-cargo:/root/.cargo/registry `
            -v wedge-zig-target:/src/target -w /src $zigImage sh scripts/build-linux.sh
    } 'Linux build'
    # The binaries are in the wedge-zig-target volume; copy them out.
    $out = Join-Path $PWD 'build/.linux'
    New-Item -ItemType Directory -Force $out | Out-Null
    $copy = ($linuxTargets | ForEach-Object {
            "mkdir -p /out/$_ && cp /t/$_/release/wedge /out/$_/wedge"
        }) -join ' && '
    Invoke-Checked {
        docker run --rm -v wedge-zig-target:/t:ro -v "${out}:/out" debian:bookworm-slim sh -c $copy
    } 'Copying Linux binaries'
    foreach ($target in $linuxTargets) {
        $layouts += New-Layout $target (Join-Path $out "$target/wedge")
    }
    Remove-Item -Recurse -Force $out
}

# Archives: tar.gz for Linux (keeps the executable bit), zip for Windows.
$artifacts = @()
foreach ($dir in $layouts) {
    $target = Split-Path $dir -Leaf
    $name = "wedge-$version-$target"
    if ($target -like '*windows*') {
        $archive = "build/$name.zip"
        if (Test-Path $archive) { Remove-Item $archive }
        Compress-Archive -Path "$dir/*" -DestinationPath $archive
    } else {
        $archive = "build/$name.tar.gz"
        Invoke-Checked { tar -czf $archive -C build $target } "Archiving $target"
    }
    $artifacts += $archive
    $artifacts += Get-ChildItem $dir -Filter 'wedge*' -File |
        Where-Object { $_.Name -in 'wedge', 'wedge.exe' } |
        ForEach-Object { $_.FullName }
}

if ($ChecksumsOnly) {
    # Every archive, package and image in build/, plus each target's binary.
    $artifacts = @(Get-ChildItem build -File | Where-Object Name -ne 'SHA256SUMS' |
            ForEach-Object { $_.FullName })
    $artifacts += Get-ChildItem build -Directory | ForEach-Object {
        Get-ChildItem $_.FullName -File | Where-Object { $_.Name -in 'wedge', 'wedge.exe' } |
            ForEach-Object { $_.FullName }
    }
}

# SHA256SUMS in the coreutils format (`sha256sum -c` reads it).
$lines = foreach ($file in $artifacts) {
    $hash = (Get-FileHash -Algorithm SHA256 $file).Hash.ToLower()
    $rel = (Resolve-Path -Relative $file).TrimStart('.', '\', '/').Replace('\', '/') -replace '^build/', ''
    "$hash  $rel"
}
[IO.File]::WriteAllText((Join-Path $PWD 'build/SHA256SUMS'), ($lines -join "`n") + "`n")
Write-Host "wrote $($artifacts.Count) checksums to build/SHA256SUMS"
Get-ChildItem build -File | Format-Table Name, Length -AutoSize
