#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) Alingan Patra
#
# Writes the CycloneDX SBOM of the wedge binary, covering the dependencies
# of every target, to build/wedge-<version>.cdx.json (Phase 7.1). Run inside
# a Rust container with the repository at /src:
#   docker run --rm -v "$PWD:/src" -w /src rust:1-bookworm sh scripts/sbom.sh
set -eu
CYCLONEDX_VERSION=0.5.9
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)

if ! cargo cyclonedx --version 2>/dev/null | grep -qF "$CYCLONEDX_VERSION"; then
    cargo install -q --locked cargo-cyclonedx --version "$CYCLONEDX_VERSION"
fi
# The commit time, not the build time, so the SBOM is reproducible.
SOURCE_DATE_EPOCH=$(git -c safe.directory='*' log -1 --format=%ct 2>/dev/null || echo 0)
export SOURCE_DATE_EPOCH

cargo cyclonedx -q --manifest-path crates/wedge/Cargo.toml --format json \
    --spec-version 1.5 --target all --override-filename sbom
mkdir -p build
mv crates/wedge/sbom.json "build/wedge-$VERSION.cdx.json"
# cargo-cyclonedx writes one file per workspace member; only wedge ships.
find crates -maxdepth 2 -name sbom.json -delete
ls -l "build/wedge-$VERSION.cdx.json"
