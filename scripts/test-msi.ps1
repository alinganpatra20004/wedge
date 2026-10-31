# SPDX-License-Identifier: Apache-2.0
# Copyright (c) Alingan Patra
#
# Installs the MSI silently, checks the service and the default site, then
# uninstalls it and checks that it is gone. For a disposable Windows machine
# with administrator rights (the release workflow runs it on a GitHub
# runner); it changes the system.
#
# Usage: pwsh scripts/test-msi.ps1 build/wedge-<version>-x86_64.msi
param([Parameter(Mandatory)][string]$Msi)
$ErrorActionPreference = 'Stop'
function Fail([string]$why) { Write-Host "FAIL: $why"; exit 1 }

$log = Join-Path ([IO.Path]::GetTempPath()) 'wedge-msi-install.log'
$p = Start-Process msiexec.exe -ArgumentList '/i', (Resolve-Path $Msi), '/qn', '/l*v', $log -Wait -PassThru
if ($p.ExitCode -ne 0) { Get-Content $log -Tail 40; Fail "install exit code $($p.ExitCode)" }
Write-Host 'installed'

$exe = 'C:\Program Files\wedge\wedge.exe'
if (-not (Test-Path $exe)) { Fail 'wedge.exe not in Program Files' }
if (-not (Test-Path 'C:\ProgramData\wedge\wedge.toml')) { Fail 'no default configuration' }
if (-not (Test-Path 'C:\Program Files\wedge\docs\html\index.html')) { Fail 'user guide (HTML) missing' }
$service = Get-CimInstance Win32_Service -Filter "Name='wedge'"
if (-not $service) { Fail 'service not registered' }
if ($service.StartName -ne 'NT SERVICE\wedge') { Fail "service runs as $($service.StartName)" }
if ($service.StartMode -ne 'Auto') { Fail "start mode $($service.StartMode)" }
Write-Host "service registered as $($service.StartName), $($service.StartMode)"

$deadline = (Get-Date).AddSeconds(30)
while ((Get-Service wedge).Status -ne 'Running' -and (Get-Date) -lt $deadline) { Start-Sleep 1 }
if ((Get-Service wedge).Status -ne 'Running') {
    Get-Content 'C:\ProgramData\wedge\logs\wedge.log' -ErrorAction SilentlyContinue
    Fail 'service did not start'
}
$response = Invoke-WebRequest http://127.0.0.1:8080/ -UseBasicParsing
if ($response.StatusCode -ne 200 -or $response.Content -notmatch 'wedge is running') { Fail 'default page not served' }
if ($response.Headers['X-Content-Type-Options'] -ne 'nosniff') { Fail 'security header missing' }
Write-Host 'service running and serving the default page'
if (-not (Get-Content 'C:\ProgramData\wedge\logs\wedge.log' -Raw).Contains('listening')) { Fail 'no service log' }
Write-Host 'service log written'

$p = Start-Process msiexec.exe -ArgumentList '/x', (Resolve-Path $Msi), '/qn' -Wait -PassThru
if ($p.ExitCode -ne 0) { Fail "uninstall exit code $($p.ExitCode)" }
if (Get-Service wedge -ErrorAction SilentlyContinue) { Fail 'service left after uninstall' }
if (Test-Path $exe) { Fail 'wedge.exe left after uninstall' }
if (-not (Test-Path 'C:\ProgramData\wedge\wedge.toml')) { Fail 'configuration was removed (must be kept)' }
Write-Host 'uninstalled; configuration kept'
Write-Host 'PASS'
