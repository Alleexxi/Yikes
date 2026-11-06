@echo off
if not exist "%~dp0.venv\Scripts\python.exe" (
  echo Run setup.ps1 first to install the local Python environment.
  exit /b 2
)
setlocal
set "PYTHONPATH=%~dp0"
"%~dp0.venv\Scripts\python.exe" -m nup_shader_audit %*
exit /b %ERRORLEVEL%
