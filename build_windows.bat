
@echo off
echo ===== RansomEye Windows Build Script =====
echo.
echo This script will build a standalone Windows executable for RansomEye
echo that includes all dependencies.
echo.
echo Building executable...
python build_windows.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Build failed! Please check the error messages above.
    pause
    exit /b %ERRORLEVEL%
)
echo.
echo Build completed successfully!
echo The executable can be found in the "dist" folder.
echo.
echo To create a Windows installer, install InnoSetup and run:
echo iscc setup_script.iss
echo.
pause
