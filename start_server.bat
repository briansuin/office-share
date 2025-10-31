
@echo off
D:
cd D:\office-share
.\venv\Scripts\waitress-serve.exe --host=0.0.0.0 --port=5000 app:app