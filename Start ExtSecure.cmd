@echo off
setlocal
cd /d "%~dp0"
set "EXTSECURE_PYTHON=C:\Users\hassa\OneDrive\Documents\ChatGPT\Alba Project\.venv\Scripts\python.exe"
if not exist "%EXTSECURE_PYTHON%" (
  echo ExtSecure Python runtime was not found. Run start_extsecure.py with your backend Python environment.
  pause
  exit /b 1
)
"%EXTSECURE_PYTHON%" start_extsecure.py
pause
