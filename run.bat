@echo off
REM ============================================================
REM  Kobra Protekt - lancement
REM  Utilise l'exe s'il existe, sinon lance directement en Python.
REM ============================================================
setlocal
cd /d "%~dp0"

if exist "dist\KobraProtekt.exe" (
  start "" "dist\KobraProtekt.exe"
  exit /b 0
)

python --version >nul 2>&1
if errorlevel 1 (
  echo Python introuvable et aucun .exe construit.
  echo Lancez d'abord build.bat, ou installez Python 3.10+.
  pause & exit /b 1
)

python -m pip install Pillow >nul 2>&1
python -m kobra_protekt
endlocal
