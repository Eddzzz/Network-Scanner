@echo off
cd /d "%~dp0backend"
if not exist ".venv312" (
    echo Creando entorno virtual...
    py -3.12 -m venv .venv312
    if errorlevel 1 exit /b 1
    call .venv312\Scripts\activate.bat
    echo Instalando dependencias...
    pip install -r requirements.txt
    if errorlevel 1 exit /b 1
) else (
    call .venv312\Scripts\activate.bat
)
set "PATH=C:\Program Files (x86)\Nmap;%PATH%"
set "PYTHONIOENCODING=utf-8"
echo.
echo Iniciando servidor...
python run.py
pause
