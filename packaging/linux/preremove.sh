#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) Alingan Patra
#
# Stops and disables the service on removal (not on upgrade). The wedge user
# and /etc/wedge are kept, so a reinstall finds its configuration again.
set -e
case "${1:-}" in
    remove|purge|0)
        if [ -d /run/systemd/system ]; then
            systemctl disable --now wedge >/dev/null 2>&1 || true
        fi
        ;;
esac
exit 0
