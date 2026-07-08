@echo off
title FireGuard Public Tunnel
echo ========================================================
echo       FireGuard Public Demo Tunnel via localhost.run
echo ========================================================
echo.
echo Make sure your FireGuard server is running (localhost:5000)
echo.
echo Connecting to tunnel server...
echo.
ssh -o StrictHostKeyChecking=no -R 80:localhost:5000 nokey@localhost.run
echo.
echo Tunnel closed. Press any key to exit.
pause > nul
