@echo off
set PYTHONPATH=
set VIRTUAL_ENV=C:\Users\Sammi\sec-dashboard\.venv
set PATH=C:\Users\Sammi\sec-dashboard\.venv\Scripts;%PATH%
cd /d C:\Users\Sammi\sec-dashboard
C:\Users\Sammi\sec-dashboard\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8444
