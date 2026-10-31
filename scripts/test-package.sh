#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) Alingan Patra
#
# Installs the wedge package in a clean distribution container and checks
# the result. Usage, from the repository root:
#   docker run --rm -v "$PWD/build:/b:ro" -v "$PWD/scripts:/s:ro" debian:12 sh /s/test-package.sh deb
#   docker run --rm -v "$PWD/build:/b:ro" -v "$PWD/scripts:/s:ro" fedora:40 sh /s/test-package.sh rpm
set -eu
kind=$1
fail() { echo "FAIL: $*"; exit 1; }

case "$kind" in
    deb)
        apt-get update -qq >/dev/null
        apt-get install -y -qq curl >/dev/null 2>&1
        install() { apt-get install -y -qq "$1" >/dev/null 2>&1 || dpkg -i "$1"; }
        pkg=$(ls /b/wedge_*_amd64.deb)
        remove() { apt-get remove -y -qq wedge >/dev/null 2>&1; }
        ;;
    rpm)
        dnf install -y -q curl-minimal util-linux >/dev/null 2>&1 || true
        install() { dnf install -y -q "$1" >/dev/null 2>&1 || rpm -i "$1"; }
        pkg=$(ls /b/wedge-*.x86_64.rpm)
        remove() { dnf remove -y -q wedge >/dev/null 2>&1; }
        ;;
    *) fail "usage: test-package.sh deb|rpm" ;;
esac

. /etc/os-release
echo "== $PRETTY_NAME: installing $(basename "$pkg")"
install "$pkg"

getent passwd wedge >/dev/null || fail "no wedge user"
shell=$(getent passwd wedge | cut -d: -f7)
case "$shell" in *nologin) ;; *) fail "wedge user has a login shell: $shell" ;; esac
[ "$(stat -c '%U:%G %a' /etc/wedge)" = "root:wedge 750" ] || fail "/etc/wedge is $(stat -c '%U:%G %a' /etc/wedge)"
[ "$(stat -c '%U:%G %a' /etc/wedge/wedge.toml)" = "root:wedge 640" ] || fail "wedge.toml is $(stat -c '%U:%G %a' /etc/wedge/wedge.toml)"
[ "$(stat -c '%U %a' /usr/bin/wedge)" = "root 755" ] || fail "/usr/bin/wedge is $(stat -c '%U %a' /usr/bin/wedge)"
[ -f /usr/lib/systemd/system/wedge.service ] || fail "no systemd unit"
echo "user, permissions and unit: OK"

wedge --version
wedge check-config -c /etc/wedge/wedge.toml

# Run as the service account, the way the systemd unit does.
setpriv --reuid=wedge --regid=wedge --clear-groups wedge run -c /etc/wedge/wedge.toml 2>/tmp/err &
pid=$!
sleep 1
body=$(curl -fsS http://127.0.0.1:8080/) || { cat /tmp/err; fail "no response"; }
echo "$body" | grep -q "wedge is running" || fail "unexpected page"
headers=$(curl -fsSI http://127.0.0.1:8080/)
echo "$headers" | grep -qi "x-content-type-options: nosniff" || fail "missing security header"
kill $pid
echo "serves the default page as the wedge user: OK"

# T6.4: an edited config survives reinstalling the package.
echo "# edited by admin" >> /etc/wedge/wedge.toml
case "$kind" in
    deb) dpkg -i --force-confold "$pkg" >/dev/null 2>&1 ;;
    rpm) rpm -U --replacepkgs "$pkg" >/dev/null 2>&1 ;;
esac
grep -q "edited by admin" /etc/wedge/wedge.toml || fail "config was overwritten on reinstall"
echo "config kept on reinstall: OK"

remove
[ ! -e /usr/bin/wedge ] || fail "binary left after removal"
echo "removed cleanly: OK"
echo "PASS $PRETTY_NAME"
