@echo off
cd /d "%~dp0backend"
if not exist "venv" (
    echo Creando entorno virtual...
    python -m venv venv
    call venv\Scripts\activate.bat
    echo Instalando dependencias...
    pip install -r requirements.txt
) else (
    call venv\Scripts\activate.bat
)
echo.
echo Iniciando servidor...
python run.py
pause
