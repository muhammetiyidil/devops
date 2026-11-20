@echo off
python "%~dp0manage-ssh" %*
exit /b %errorlevel%
