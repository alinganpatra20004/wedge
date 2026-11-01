@echo off
rem SPDX-License-Identifier: Apache-2.0
rem Copyright (c) OpenEdge Labs
rem
rem Controls the wEdge service; the Start menu and install-folder shortcuts
rem run it. Usage: wedge-control.cmd start|stop|restart|status|reload|edit
rem
rem   edit  opens the configuration in Notepad, then checks it and reloads
rem         the service when you press a key.
rem
rem Everything except "status" needs administrator rights, so the script
rem asks for them (UAC) and runs itself again elevated.
setlocal
set "ACTION=%~1"
if not defined ACTION set "ACTION=status"
for %%A in (start stop restart status reload edit) do if /i "%ACTION%"=="%%A" goto known
echo usage: %~nx0 start^|stop^|restart^|status^|reload^|edit
exit /b 2

:known
if /i "%ACTION%"=="status" goto run
net session >nul 2>&1
if not errorlevel 1 goto run
rem Paths and the action reach PowerShell through the environment, never
rem through the command text, so no folder name can change the command.
set "WEDGE_SELF=%~f0"
powershell.exe -NoProfile -NonInteractive -Command "Start-Process -FilePath $env:WEDGE_SELF -ArgumentList $env:ACTION -Verb RunAs"
exit /b

:run
set "WEDGE=%~dp0wedge.exe"
if /i "%ACTION%"=="edit" goto edit
"%WEDGE%" service %ACTION%
goto done

:edit
set "CONFIG="
for /f "tokens=2,*" %%a in ('reg query "HKLM\SOFTWARE\wedge" /v ConfigFile 2^>nul ^| find "ConfigFile"') do set "CONFIG=%%b"
if not defined CONFIG (
  echo The configuration path is not recorded; reinstall wEdge or edit the file directly.
  goto done
)
echo Opening %CONFIG%
start "" notepad.exe "%CONFIG%"
echo.
echo Save your changes in Notepad, then press a key here to check and apply them.
pause >nul
"%WEDGE%" check-config -c "%CONFIG%"
if errorlevel 1 (
  echo The configuration has errors; the service keeps running the previous one.
  goto done
)
"%WEDGE%" service reload

:done
echo.
pause
