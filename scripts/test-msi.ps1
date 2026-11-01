# SPDX-License-Identifier: Apache-2.0
# Copyright (c) Alingan Patra
#
# Tests the MSI on a disposable Windows machine with administrator rights
# (the release and installer workflows run it on a GitHub runner); it
# installs services and changes the system.
#
#   1. Fresh install with a custom folder, ports, public access and an
#      administrator account: files, folder permissions, service, website,
#      admin login, firewall rule, shortcuts, service control, reload, and
#      that the password never reaches the installer log; then uninstall.
#   2. With -PreviousMsi (an older release): upgrade keeps its configuration,
#      content and locations.
#   3. With -PreviousMsi: "uninstall it and install fresh" with "delete its
#      data" removes the old configuration and content.
#
# Usage: pwsh scripts/test-msi.ps1 build/wedge-<version>-x86_64.msi [-PreviousMsi <older.msi>]
param(
    [Parameter(Mandatory)][string]$Msi,
    [string]$PreviousMsi
)
$ErrorActionPreference = 'Stop'
$Msi = (Resolve-Path $Msi).Path
function Fail([string]$why) { Write-Host "FAIL: $why"; exit 1 }
function Pass([string]$what) { Write-Host "  ok: $what" }
$logDir = Join-Path ([IO.Path]::GetTempPath()) 'wedge-msi-logs'
New-Item -ItemType Directory -Force $logDir | Out-Null
$password = 'correct horse battery staple'

function Invoke-Msi([string]$name, [string]$arguments) {
    $log = Join-Path $logDir "$name.log"
    $p = Start-Process msiexec.exe -ArgumentList "$arguments /qn /l*v `"$log`"" -Wait -PassThru
    if ($p.ExitCode -ne 0) {
        Get-Content $log -Encoding Unicode | Select-String -Pattern 'error|failed|return value 3' -Context 2, 2 |
            Select-Object -Last 15 | ForEach-Object { $_.ToString() }
        Fail "$name exit code $($p.ExitCode)"
    }
    $log
}

function Wait-Running {
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Service wedge -ErrorAction SilentlyContinue).Status -ne 'Running' -and (Get-Date) -lt $deadline) {
        Start-Sleep 1
    }
    if ((Get-Service wedge -ErrorAction SilentlyContinue).Status -ne 'Running') { Fail 'service is not running' }
}

function Get-Page([string]$url, [string]$user, [string]$pass) {
    $headers = @{}
    if ($user) {
        $pair = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("${user}:$pass"))
        $headers['Authorization'] = "Basic $pair"
    }
    try {
        Invoke-WebRequest $url -UseBasicParsing -Headers $headers
    } catch {
        $_.Exception.Response
    }
}

function Assert-Locked([string]$path) {
    $acl = Get-Acl -LiteralPath $path
    if (-not $acl.AreAccessRulesProtected) { Fail "$path inherits permissions" }
    $sid = [Security.Principal.SecurityIdentifier]
    $write = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, Delete, ChangePermissions, TakeOwnership'
    foreach ($rule in $acl.GetAccessRules($true, $true, $sid)) {
        $who = $rule.IdentityReference.Value
        if ($who -in 'S-1-5-18', 'S-1-5-32-544') { continue }
        if ($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $write)) {
            Fail "$path gives $who $($rule.FileSystemRights)"
        }
    }
}

# --- 1. Fresh install with every choice made ------------------------------
Write-Host '== fresh install, custom choices'
$root = 'C:\wedge test'
$log = Invoke-Msi 'fresh' "/i `"$Msi`" INSTALLFOLDER=`"$root`" HTTPPORT=8081 ADMINPORT=9091 ADMINUSER=admin ADMINPASSWORD=`"$password`" PUBLICACCESS=1"
$exe = "$root\wedge.exe"
$config = "$root\conf\wedge.toml"
foreach ($file in $exe, "$root\wedge-control.cmd", $config, "$root\conf\admin-users.txt",
    "$root\www\index.html", "$root\www\.wedge-created", "$root\docs\html\index.html") {
    if (-not (Test-Path -LiteralPath $file)) { Fail "missing $file" }
}
Pass 'files installed and configuration written'
Assert-Locked $root
Assert-Locked "$root\conf"
$users = Get-Acl -LiteralPath "$root\conf\admin-users.txt"
if (-not $users.AreAccessRulesProtected -or ($users.Access.IdentityReference.Value -match 'Users$')) {
    Fail 'the users file is readable by ordinary users'
}
Pass 'install and configuration folders locked; users file private'
if ((Get-Content $log -Raw -Encoding Unicode).Contains($password)) { Fail 'the password is in the installer log' }
if ((Get-Content $config -Raw).Contains($password) -or (Get-Content "$root\conf\admin-users.txt" -Raw).Contains($password)) {
    Fail 'the password is stored in clear'
}
Pass 'password not in the log or on disk'
if (-not (Get-Content $config -Raw).Contains('listen = ["0.0.0.0:8081"]')) { Fail 'public listen address not written' }

$service = Get-CimInstance Win32_Service -Filter "Name='wedge'"
if (-not $service) { Fail 'service not registered' }
if ($service.StartName -ne 'NT SERVICE\wedge') { Fail "service runs as $($service.StartName)" }
if ($service.StartMode -ne 'Auto') { Fail "start mode $($service.StartMode)" }
if (-not $service.PathName.Contains($root)) { Fail "service path $($service.PathName)" }
Wait-Running
Pass "service running as $($service.StartName) from $root"

$site = Get-Page 'http://127.0.0.1:8081/'
if ($site.StatusCode -ne 200 -or $site.Content -notmatch 'wedge is running') { Fail 'default page not served' }
if ($site.Headers['X-Content-Type-Options'] -ne 'nosniff') { Fail 'security header missing' }
Pass 'website served on port 8081'
if ([int](Get-Page 'http://127.0.0.1:9091/').StatusCode -ne 401) { Fail 'admin page answers without a login' }
if ([int](Get-Page 'http://127.0.0.1:9091/' 'admin' 'wrong password here').StatusCode -ne 401) { Fail 'wrong password accepted' }
$admin = Get-Page 'http://127.0.0.1:9091/' 'admin' $password
if ($admin.StatusCode -ne 200 -or $admin.Content -notmatch 'Signed in as admin') { Fail 'admin login failed' }
if ((Get-Page 'http://127.0.0.1:9091/metrics' 'admin' $password).StatusCode -ne 200) { Fail 'metrics not served' }
Pass 'admin page needs the login and works with it'

if (-not (Get-NetFirewallRule -DisplayName 'wEdge web server' -ErrorAction SilentlyContinue)) { Fail 'firewall rule missing' }
Pass 'firewall rule added'
$settings = Get-ItemProperty 'HKLM:\SOFTWARE\wedge'
if ($settings.ConfigFile -ne $config -or $settings.AdminPort -ne '9091' -or $settings.Public -ne '1') {
    Fail "recorded settings: $($settings | Out-String)"
}
$menu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\wEdge'
foreach ($link in "$menu\Start wEdge.lnk", "$menu\Stop wEdge.lnk", "$menu\Edit wEdge configuration.lnk",
    "$menu\Uninstall wEdge.lnk", "$menu\wEdge admin page.url", "$root\Start wEdge.lnk",
    "$root\Stop wEdge.lnk", "$root\Uninstall wEdge.lnk", "$root\wEdge admin page.url") {
    if (-not (Test-Path -LiteralPath $link)) { Fail "missing shortcut $link" }
}
Pass 'settings recorded; Start menu and install-folder shortcuts present'

$status = '' | & cmd.exe /c "`"$root\wedge-control.cmd`" status" 2>&1 | Out-String
if ($status -notmatch 'running') { Fail "wedge-control status: $status" }
$restart = & $exe service restart 2>&1 | Out-String
if ($restart -notmatch 'running') { Fail "service restart: $restart" }
Wait-Running
& $exe service reload | Out-Null
Start-Sleep 2
if (-not (Get-Content "$root\logs\wedge.log" -Raw).Contains('configuration reloaded')) { Fail 'reload not logged' }
Pass 'control script, restart and reload work; log in the install folder'

Invoke-Msi 'fresh-uninstall' "/x `"$Msi`"" | Out-Null
if (Get-Service wedge -ErrorAction SilentlyContinue) { Fail 'service left after uninstall' }
if (Test-Path -LiteralPath $exe) { Fail 'wedge.exe left after uninstall' }
if (-not (Test-Path -LiteralPath $config)) { Fail 'configuration removed (must be kept)' }
if (Test-Path -LiteralPath $menu) { Fail 'Start menu folder left' }
if (Get-NetFirewallRule -DisplayName 'wEdge web server' -ErrorAction SilentlyContinue) { Fail 'firewall rule left' }
Pass 'uninstalled; configuration kept, shortcuts and firewall rule removed'
Remove-Item -LiteralPath $root -Recurse -Force

if (-not $PreviousMsi) { Write-Host 'PASS (no previous release given: upgrade not tested)'; exit 0 }
$PreviousMsi = (Resolve-Path $PreviousMsi).Path
$legacy = Join-Path $env:ProgramData 'wedge'

# --- 2. Upgrade an older release, keeping everything ----------------------
Write-Host "== upgrade from $(Split-Path $PreviousMsi -Leaf)"
Invoke-Msi 'previous' "/i `"$PreviousMsi`"" | Out-Null
Wait-Running
Set-Content -LiteralPath "$legacy\www\custom.html" -Value 'my own page'
Invoke-Msi 'upgrade' "/i `"$Msi`"" | Out-Null
Wait-Running
$service = Get-CimInstance Win32_Service -Filter "Name='wedge'"
if (-not $service.PathName.Contains("$legacy\wedge.toml")) { Fail "upgrade changed the configuration: $($service.PathName)" }
if ((Get-Page 'http://127.0.0.1:8080/custom.html').Content -notmatch 'my own page') { Fail 'upgrade lost the site content' }
$version = & 'C:\Program Files\wedge\wedge.exe' --version
$expected = (Split-Path $Msi -Leaf) -replace '^wedge-(.+)-x86_64\.msi$', '$1'
if ($version -notmatch [regex]::Escape($expected)) { Fail "upgraded binary reports $version" }
$installed = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' |
        Get-ItemProperty | Where-Object DisplayName -EQ 'wEdge')
if ($installed.Count -ne 1) { Fail "$($installed.Count) wEdge products installed after the upgrade" }
if ((Get-ItemProperty 'HKLM:\SOFTWARE\wedge').ConfigFolder -ne "$legacy\") { Fail 'upgrade did not record the kept folders' }
Pass "upgraded to $version; configuration, content and folders kept"
Invoke-Msi 'upgrade-uninstall' "/x `"$Msi`"" | Out-Null

# --- 3. Uninstall the older release and install fresh, deleting its data --
Write-Host '== uninstall previous, install fresh, delete its data'
Invoke-Msi 'previous-again' "/i `"$PreviousMsi`"" | Out-Null
Wait-Running
Invoke-Msi 'fresh-purge' "/i `"$Msi`" UPGRADEMODE=fresh PURGEOLD=1 ADMINPASSWORD=`"$password`"" | Out-Null
Wait-Running
if (Test-Path -LiteralPath "$legacy\wedge.toml") { Fail 'old configuration not deleted' }
if (Test-Path -LiteralPath "$legacy\www") { Fail 'old web content not deleted' }
$service = Get-CimInstance Win32_Service -Filter "Name='wedge'"
if (-not $service.PathName.Contains('C:\Program Files\wedge\conf\wedge.toml')) { Fail "fresh install config: $($service.PathName)" }
if ((Get-Page 'http://127.0.0.1:8080/').StatusCode -ne 200) { Fail 'fresh install does not serve' }
if ([int](Get-Page 'http://127.0.0.1:9090/').StatusCode -ne 401) { Fail 'fresh install admin page open' }
Pass 'old data deleted; fresh configuration in the install folder; admin page protected'
Invoke-Msi 'fresh-purge-uninstall' "/x `"$Msi`"" | Out-Null
Write-Host 'PASS'
