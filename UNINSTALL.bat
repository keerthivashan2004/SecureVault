@echo off
title FolderLocker - Uninstaller
color 0C

echo.
echo  ==========================================
echo     FolderLocker - Uninstall
echo  ==========================================
echo.
echo  This will remove the right-click context menu entry.
echo  Your locked folders will remain locked until you unlock them.
echo.
set /p "confirm=Are you sure? (Y/N): "
if /i not "%confirm%"=="Y" goto :cancel

python "%~dp0folder_locker.py" uninstall

echo.
echo  Done. Context menu removed.
echo.
pause
exit /b 0

:cancel
echo  Uninstall cancelled.
pause
