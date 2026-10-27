@echo off
REM Genera SecretEncryptor.exe en la carpeta dist
python -m pip install --upgrade cryptography pyinstaller
python -m PyInstaller --onefile --windowed --name SecretEncryptor SecretEncryptor.py
echo.
echo Ejecutable generado en: %~dp0dist\SecretEncryptor.exe
pause
