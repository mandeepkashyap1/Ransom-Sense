@echo off
title OK Sentinel - Security Operations Center
color 0B
echo ===================================================
echo   Starting OK Sentinel Real-Time Security Watcher
echo ===================================================
echo.
start "" "http://localhost:8080/main.html"
node server.js

