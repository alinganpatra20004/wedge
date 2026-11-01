#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OpenEdge Labs
#
# Sets ownership of /etc/wedge (root-owned, readable by the wedge group only;
# threat model T6.5) and tells systemd about the unit. The service is not
# started automatically: review the configuration first.
set -e
chown root:wedge /etc/wedge /etc/wedge/conf.d /etc/wedge/wedge.toml
chmod 0750 /etc/wedge /etc/wedge/conf.d
chmod 0640 /etc/wedge/wedge.toml
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
echo "wedge installed. Review /etc/wedge/wedge.toml, then: systemctl enable --now wedge"
exit 0
