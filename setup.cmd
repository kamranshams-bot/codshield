@echo off
rem CODShield: connect to Neon, test, and start the app. Double-click to run.
cd /d "%~dp0"
setlocal

where node >nul 2>nul || (echo [X] Node.js is not installed. Get the LTS version from https://nodejs.org then run this again. & goto :end)
where python >nul 2>nul || (echo [X] Python is not installed. Get Python 3.12 from https://python.org ^(tick "Add python.exe to PATH"^) then run this again. & goto :end)

echo.
echo === 1/6  Installing the Neon CLI ===
call npm i -g neon@latest || (echo [X] npm install failed & goto :end)

echo.
echo === 2/6  Signing in to Neon (a browser window will open; finish sign-in there) ===
call neon me >nul 2>nul || call neon login || (echo [X] Neon sign-in failed. Run "neon login" in this folder, then run this file again. & goto :end)

echo.
echo === 3/6  Linking this folder to your Neon project ===
call neon init -y --org-id org-royal-pond-93949091 --project-id calm-poetry-51784258 --branch production --services postgres || (echo [X] neon init failed & goto :end)

echo.
echo === 4/6  Provisioning and pulling the database connection (neon deploy) ===
call neon deploy || (echo [X] neon deploy failed & goto :end)

echo.
echo === 5/6  Installing Python packages and running checks ===
python -m pip install -q -r requirements.txt || (echo [X] pip install failed & goto :end)
python -m pytest -q || (echo [X] unit tests failed & goto :end)
python verify_neon.py || (echo [X] Neon end-to-end check failed & goto :end)

if not exist ".env.local" if not exist ".env" goto :end
findstr /b /c:"CODSHIELD_HASH_SECRET=" .env.local .env >nul 2>nul || (
  for /f %%k in ('python -c "import secrets;print(secrets.token_urlsafe(48))"') do echo CODSHIELD_HASH_SECRET=%%k>> .env.local
  for /f %%k in ('python -c "import secrets;print(secrets.token_urlsafe(24))"') do echo CODSHIELD_ADMIN_KEY=%%k>> .env.local
  echo Created your hash secret and admin key in .env.local. Back that file up; never change the hash secret.
)

echo.
echo === 6/6  Starting CODShield at http://localhost:8000  (close this window to stop) ===
for /f "tokens=2 delims==" %%a in ('findstr /b /c:"CODSHIELD_ADMIN_KEY=" .env.local') do echo Your admin key: %%a
start "" http://localhost:8000
python -m uvicorn codshield.api:app --port 8000

:end
echo.
pause
