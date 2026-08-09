@echo off
echo Starting Trendora...
if not exist node_modules call npm install
node server.js
pause
