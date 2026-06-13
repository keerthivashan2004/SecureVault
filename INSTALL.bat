@echo off
title FolderLocker - Installer
color 0A

echo.
echo  ==========================================
echo     FolderLocker - Windows Folder Security
echo  ==========================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python is not installed or not in PATH.
    echo  Please install Python 3.9+ from https://python.org
    pause
    exit /b 1
)

echo  [1/3] Installing required Python packages...
pip install cryptography --quiet
if errorlevel 1 (
    echo  [ERROR] Failed to install cryptography package.
    pause
    exit /b 1
)
echo         Done.

echo.
echo  [2/3] Registering right-click context menu...
python "%~dp0folder_locker.py" install
if errorlevel 1 (
    echo  [ERROR] Failed to register context menu.
    echo         Try running this batch file as Administrator.
    pause
    exit /b 1
)
echo         Done.

echo.
echo  [3/3] Creating desktop shortcut (optional)...
echo  Skipped (not required).

echo.
echo  ==========================================
echo   Installation Complete!
echo  ==========================================
echo.
echo   How to use:
echo   1. Right-click any folder on your Desktop or Explorer
echo   2. Select "Lock / Unlock Folder"
echo   3. Set a password to lock, or enter it to unlock
echo.
pause
