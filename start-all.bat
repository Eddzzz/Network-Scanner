@echo off
echo Iniciando Backend y Frontend...
echo.
start cmd /k "%~dp0start-backend.bat"
timeout /t 3 /nobreak >nul
start cmd /k "%~dp0start-frontend.bat"
echo.
echo Aplicacion iniciada
echo.
echo Backend:  http://localhost:8000
echo Frontend: http://localhost:3000
echo Docs:     http://localhost:8000/docs
echo.
pause
