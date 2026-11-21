@echo off
REM Train the PE model once the dataset is in place (see ai\malware-pe\README.md)
cd /d "%~dp0"
.venv\Scripts\python -m pip install -r ai\malware-pe\requirements.txt
.venv\Scripts\python ai\malware-pe\train.py %*
pause
