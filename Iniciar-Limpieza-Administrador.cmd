@echo off
setlocal DisableDelayedExpansion
title Lanzador de limpieza DAM
rem LIMPIEZA REAL. Mantener este archivo junto a Limpiar-RastrosAlumno.ps1.
rem No modifica asociaciones de archivos ni la politica permanente de PowerShell.
set "DAM_CLEANUP_LAUNCH_SCRIPT=%~dp0Limpiar-RastrosAlumno.ps1"
set "DAM_CLEANUP_LAUNCH_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "DAM_CLEANUP_LAUNCH_PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%DAM_CLEANUP_LAUNCH_SCRIPT%" goto missing_script
if not exist "%DAM_CLEANUP_LAUNCH_PS%" goto missing_powershell
echo Se solicitara permiso de administrador para ejecutar la LIMPIEZA REAL.
echo Si acepta UAC, el script comenzara sin mas preguntas.
"%DAM_CLEANUP_LAUNCH_PS%" -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; try { if (-not [Environment]::Is64BitProcess) { throw 'Se requiere Windows de 64 bits.' }; $scriptPath=$env:DAM_CLEANUP_LAUNCH_SCRIPT; if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { throw 'No se encuentra Limpiar-RastrosAlumno.ps1 junto al lanzador.' }; $quotedPath=$scriptPath.Replace([string][char]39,([string][char]39 + [char]39)); $payload='$ErrorActionPreference=''Stop''; Write-Host ''LIMPIEZA REAL DEL EQUIPO. MariaDB de XAMPP esta excluido.'' -ForegroundColor Yellow; try { & ''' + $quotedPath + '''; $cleanupCode=$LASTEXITCODE } catch { $cleanupCode=1; Write-Host $_.Exception.Message -ForegroundColor Red }; Write-Host (''Codigo de resultado: '' + $cleanupCode); Write-Host ''0: terminado. 1: error/bloqueo. 2: revision pendiente.''; Write-Host ''Revise el resultado y los informes. No repita la limpieza para resolver avisos.''; Write-Host ''Puede cerrar esta ventana cuando termine de revisarla.'''; $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload)); $ps64=Join-Path $PSHOME 'powershell.exe'; Start-Process -FilePath $ps64 -Verb RunAs -WindowStyle Normal -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-EncodedCommand',$encoded) -ErrorAction Stop | Out-Null; exit 0 } catch { Write-Host ('No se ha podido lanzar la limpieza: ' + $_.Exception.Message) -ForegroundColor Red; exit 1 }"
if errorlevel 1 goto launch_error
exit /b 0

:missing_script
echo ERROR: Falta Limpiar-RastrosAlumno.ps1 junto a este lanzador.
goto launch_error

:missing_powershell
echo ERROR: No se encuentra Windows PowerShell.
goto launch_error

:launch_error
echo No se ha iniciado la limpieza desde este lanzador.
echo Si rechazo UAC, no se ha ejecutado el script.
pause
exit /b 1
