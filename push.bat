@echo off
chcp 65001 >nul
title Загрузка Heavenly Backend на GitHub
echo ===================================================
echo     Загрузка Heavenly Backend в репозиторий:
echo     https://github.com/Roman32423/heavenly-auth
echo ===================================================
echo.
cd /d "%~dp0"
git remote remove origin 2>nul
git remote add origin https://github.com/Roman32423/heavenly-auth.git
git branch -M main
git push -u origin main
echo.
if %ERRORLEVEL% EQU 0 (
    echo [УСПЕХ] Все файлы успешно загружены на GitHub!
) else (
    echo [ОШИБКА] Проверьте подключение или авторизуйтесь в GitHub.
)
pause
