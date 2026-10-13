@echo off
REM ============================================================
REM  Kobra Protekt - construction de l'executable Windows (.exe)
REM  A lancer sur Windows. Produit dist\KobraProtekt.exe
REM ============================================================
setlocal
cd /d "%~dp0"

echo [1/4] Verification de Python...
python --version >nul 2>&1
if errorlevel 1 (
  echo   Python introuvable. Installez Python 3.10+ depuis https://www.python.org
  echo   ^(cochez "Add python.exe to PATH" pendant l'installation^)
  pause & exit /b 1
)

echo [2/4] Installation des dependances...
python -m pip install --upgrade pip >nul
python -m pip install pyinstaller Pillow
if errorlevel 1 ( echo   Echec de l'installation. & pause & exit /b 1 )

echo [3/4] Construction de l'executable...
python -m PyInstaller --noconfirm --clean --onefile --windowed ^
  --name KobraProtekt ^
  --icon "assets\kobra.ico" ^
  --add-data "assets;assets" ^
  kobra_protekt\__main__.py
if errorlevel 1 ( echo   Echec de la construction. & pause & exit /b 1 )

echo [4/4] Termine.
echo.
echo   Executable : dist\KobraProtekt.exe
echo   Lancez-le directement, ou utilisez run.bat
echo.
pause
endlocal
