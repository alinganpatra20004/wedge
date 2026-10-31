#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) Alingan Patra
#
# Creates the wedge system user and group (threat model T6.3). Runs as root;
# touches nothing else.
set -e
if ! getent group wedge >/dev/null 2>&1; then
    groupadd --system wedge
fi
if ! getent passwd wedge >/dev/null 2>&1; then
    nologin=/usr/sbin/nologin
    [ -x "$nologin" ] || nologin=/sbin/nologin
    useradd --system --gid wedge --no-create-home --home-dir /nonexistent \
        --shell "$nologin" --comment "wedge web server" wedge
fi
exit 0
