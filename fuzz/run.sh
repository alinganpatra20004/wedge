#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) Alingan Patra
#
# Runs every fuzz target for SECONDS (default 60) each. Needs Linux and the
# nightly toolchain; on other hosts run it inside the rust Docker image:
#   docker run --rm -v "$PWD:/src" -w /src rust:latest sh fuzz/run.sh 60
set -eu
SECONDS_PER_TARGET=${1:-60}
rustup toolchain install nightly --profile minimal >/dev/null 2>&1 || true
command -v cargo-fuzz >/dev/null 2>&1 || cargo install --locked cargo-fuzz
cd "$(dirname "$0")/.."
for target in $(cargo +nightly fuzz list); do
  echo "== $target (${SECONDS_PER_TARGET}s)"
  cargo +nightly fuzz run "$target" -- -max_total_time="$SECONDS_PER_TARGET" -max_len=8192
done
