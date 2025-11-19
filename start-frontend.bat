@echo off
cd /d "%~dp0frontend"
if not exist "node_modules" (
    echo Instalando dependencias...
    npm install
)
echo.
echo Iniciando servidor...
npm run dev
pause
