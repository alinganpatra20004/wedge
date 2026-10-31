<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) Alingan Patra -->
# Running as a service

## systemd (Debian, Ubuntu, Kali, Fedora, RHEL)

The .deb and .rpm packages install `/usr/lib/systemd/system/wedge.service`
and a `wedge` system user. Enable and start it:

```sh
sudo systemctl enable --now wedge
systemctl status wedge
journalctl -u wedge -f            # follow the logs
sudo systemctl reload wedge       # apply configuration changes
```

The unit checks the configuration before starting (`ExecStartPre`), runs as
the `wedge` user with only the right to bind ports below 1024, and applies
systemd's sandboxing (read-only system, no home directories, private `/tmp`
and devices, restricted system calls, no core dumps). `systemd-analyze
security wedge` rates it 1.6 ("OK") on its 0–10 exposure scale.

To change environment variables (for example the log format) without
editing the packaged unit:

```sh
sudo systemctl edit wedge
# [Service]
# Environment=WEDGE_LOG_FORMAT=json
```

If a document root is outside `/srv`, `/var/www` or `/usr/share`, it is still
readable (the system is read-only, not hidden), but files must be readable by
the `wedge` user.

## OpenRC (Alpine)

The Linux tarballs include `openrc/wedge`; the
[Alpine guide](../install/alpine-3.20.md) installs it:

```sh
sudo rc-update add wedge default
sudo rc-service wedge start
sudo rc-service wedge reload
```

Logs go to `/var/log/wedge.log`.

## Windows service

From an elevated PowerShell, with `wedge.exe` copied to
`C:\Program Files\wedge\`:

```powershell
& 'C:\Program Files\wedge\wedge.exe' service install -c C:\ProgramData\wedge\wedge.toml
Start-Service wedge
sc.exe control wedge paramchange      # reload the configuration
& 'C:\Program Files\wedge\wedge.exe' service uninstall
```

- The service runs as the virtual account `NT SERVICE\wedge`, not as
  LocalSystem. Install grants it read access to the configuration folder and
  write access to `C:\ProgramData\wedge\logs` only.
- It starts automatically at boot and restarts after a crash (three times,
  5 seconds apart).
- Install refuses a `wedge.exe` outside Program Files, because ordinary users
  could replace a binary elsewhere and have it run as the service. For a test
  machine only, `--allow-unprotected-path` skips the check.

## Containers

The OCI image contains only the static binary, a default configuration and a
test page, and runs as user 65532:

```sh
docker load -i wedge-0.1.1-oci-amd64.tar
docker run -d --name wedge --read-only --cap-drop ALL \
  --security-opt no-new-privileges -p 8080:8080 \
  -v /srv/site:/srv/www:ro -v /etc/wedge:/etc/wedge:ro wedge:0.1.1
```

Inside the container wedge listens on `0.0.0.0:8080`; choose the exposure
with `-p`. To bind port 80 inside the container instead, add
`--cap-add NET_BIND_SERVICE`. Reload with `docker kill -s HUP wedge`.
