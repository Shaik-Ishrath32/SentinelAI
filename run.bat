@echo off
cd backend
if not exist .venv ( python -m venv .venv )
call .venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --port 8000
