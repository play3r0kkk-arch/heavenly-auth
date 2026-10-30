@echo off
cd /d "%~dp0"
git remote remove origin 2>nul
git remote add origin https://github.com/play3r0kkk-arch/heavenly-auth.git
git branch -M main
git add .
git commit -m "Update backend"
git push -u origin main
pause
