#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OpenEdge Labs
#
# Renders the wEdge logo sources into the raster files the installers need.
# Run from the repository root in a Debian container:
#   docker run --rm -v "$PWD:/src" -w /src debian:bookworm sh scripts/render-branding.sh
set -eu
apt-get update -qq >/dev/null
apt-get install -y -qq librsvg2-bin imagemagick fonts-dejavu-core >/dev/null 2>&1
out=packaging/branding/generated
mkdir -p "$out"
for size in 16 24 32 48 64 128 256 512; do
    rsvg-convert -w "$size" -h "$size" packaging/branding/wedge-icon.svg -o "$out/wedge-$size.png"
done
# Windows icon with every size Explorer and the taskbar use.
convert "$out/wedge-16.png" "$out/wedge-24.png" "$out/wedge-32.png" "$out/wedge-48.png" \
    "$out/wedge-64.png" "$out/wedge-128.png" "$out/wedge-256.png" "$out/wedge.ico"
rsvg-convert -w 960 packaging/branding/wedge-logo.svg -o "$out/wedge-logo.png"
# MSI dialog artwork: banner 493x58 and side image 493x312 (WiX UI sizes).
rsvg-convert -h 46 packaging/branding/wedge-logo.svg -o /tmp/logo-46.png
convert -size 493x58 xc:white /tmp/logo-46.png -gravity east -geometry +12+0 -composite \
    BMP3:"$out/msi-banner.bmp"
rsvg-convert -w 150 packaging/branding/wedge-icon.svg -o /tmp/icon-150.png
convert -size 493x312 gradient:'#0B1F3A'-'#123A66' /tmp/icon-150.png -gravity northwest \
    -geometry +12+24 -composite BMP3:"$out/msi-dialog.bmp"
chmod -R a+rwX "$out"
ls -l "$out"
