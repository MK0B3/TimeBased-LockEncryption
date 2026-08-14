@echo off
echo ================================================================
echo   TIME-LOCKED MESSAGE CAPSULE
echo ================================================================
echo.
echo Starting server with built-in decryption service...
echo.
echo Once you see "Starting server on http://localhost:8080"
echo open your browser to: http://localhost:8080
echo.
echo Press Ctrl+C to stop the server when done.
echo.
echo ================================================================
echo.
cd /d "%~dp0"
go run ./cmd/server
pause
