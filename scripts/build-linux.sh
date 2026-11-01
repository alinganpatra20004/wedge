#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OpenEdge Labs
#
# Cross-builds the Linux release binaries with cargo-zigbuild. Run inside the
# ghcr.io/rust-cross/cargo-zigbuild image with the repository at /src, as
# scripts/build-all.ps1 and the release workflow do:
#   docker run --rm -v "$PWD:/src" -w /src ghcr.io/rust-cross/cargo-zigbuild:0.20.1 \
#       sh scripts/build-linux.sh
# Binaries land in target/<triple>/release/wedge.
set -eu

TARGETS="x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-musl"

# cargo-auditable embeds the dependency list in each binary for cargo-audit
# and Trivy (Phase 7.1). The version comes from scripts/build-all.ps1.
AUDITABLE_VERSION=${AUDITABLE_VERSION:-0.7.7}
if ! cargo auditable --version 2>/dev/null | grep -qF "$AUDITABLE_VERSION"; then
    cargo install -q --locked cargo-auditable --version "$AUDITABLE_VERSION"
fi

# Keep build-machine paths out of the binaries (threat model T6.8).
export RUSTFLAGS="--remap-path-prefix=$(pwd)=/build/wedge --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"

for target in $TARGETS; do
    rustup target add "$target" >/dev/null 2>&1
    case "$target" in
        # glibc 2.17 keeps the gnu binaries running on older distributions.
        *-gnu) zig_target="$target.2.17" ;;
        *) zig_target="$target" ;;
    esac
    echo "== $target"
    cargo auditable zigbuild --release --locked -p wedge --target "$zig_target"
done
