#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) Alingan Patra
#
# Builds the wedge OCI image for this machine's architecture from the musl
# binary in build/ and saves it as build/wedge-<version>-oci-<arch>.tar.
# Usage (repository root, Docker running): sh scripts/build-oci.sh [amd64|arm64]
set -eu
ARCH=${1:-amd64}
case "$ARCH" in
    amd64) TARGET=x86_64-unknown-linux-musl ;;
    arm64) TARGET=aarch64-unknown-linux-musl ;;
    *) echo "unknown arch $ARCH" >&2; exit 1 ;;
esac
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
docker build --platform "linux/$ARCH" -f packaging/oci/Dockerfile \
    --build-arg "TARGET=$TARGET" --build-arg "VERSION=$VERSION" \
    -t "wedge:$VERSION" .
docker save "wedge:$VERSION" -o "build/wedge-$VERSION-oci-$ARCH.tar"
echo "built wedge:$VERSION ($ARCH) -> build/wedge-$VERSION-oci-$ARCH.tar"
