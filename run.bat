@echo off
chcp 65001 >nul
title Heavenly Auth Backend
echo ===================================================
echo     HEAVENLY CLIENT AUTH BACKEND API (FastAPI)
echo ===================================================
echo.
echo Запуск сервера на http://127.0.0.1:8000
echo Документация API доступна на http://127.0.0.1:8000/docs
echo.
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
pause
