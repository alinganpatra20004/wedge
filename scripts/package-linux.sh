#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) Alingan Patra
#
# Builds the .deb and .rpm packages for amd64 and arm64 from the static musl
# binaries in build/ (made by scripts/build-all.ps1 or the release workflow).
# Run inside the nfpm image with the repository at /src:
#   docker run --rm -v "$PWD:/src" -w /src --entrypoint sh \
#       goreleaser/nfpm:v2.41.1 scripts/package-linux.sh
set -eu
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
export VERSION
# GPG_PRIVATE_KEY (armored, from the release workflow's secret) signs the
# packages. It is written to a private temporary file, never printed.
NFPM_SIGNING_KEY_FILE=""
if [ -n "${GPG_PRIVATE_KEY:-}" ]; then
    # mktemp creates the file 0600; the umask is not changed, so the
    # packages built below stay readable.
    NFPM_SIGNING_KEY_FILE=$(mktemp)
    printf '%s\n' "$GPG_PRIVATE_KEY" > "$NFPM_SIGNING_KEY_FILE"
    trap 'rm -f "$NFPM_SIGNING_KEY_FILE"' EXIT
    echo "signing packages"
fi
export NFPM_SIGNING_KEY_FILE
for pair in amd64:x86_64-unknown-linux-musl arm64:aarch64-unknown-linux-musl; do
    ARCH=${pair%%:*}
    TARGET=${pair#*:}
    export ARCH TARGET
    if [ ! -x "build/$TARGET/wedge" ]; then
        echo "missing build/$TARGET/wedge; run scripts/build-all.ps1 first" >&2
        exit 1
    fi
    mkdir -p build/.pkg
    cp "build/$TARGET/wedge" build/.pkg/wedge
    for format in deb rpm; do
        nfpm package --config packaging/nfpm.yaml --packager "$format" --target build/
    done
done
rm -rf build/.pkg
ls -l build/*.deb build/*.rpm
