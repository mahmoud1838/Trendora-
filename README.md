# Trendora V6 — Online-ready

## Why "Failed to fetch" happened
Trendora V6 is no longer a standalone HTML file. The Create Account button calls the Node/Express authentication API.
Opening `public/index.html` directly with `file://` gives the browser no server to call, so it reports `Failed to fetch`.

## Easiest local test
1. Install Node.js 18+.
2. Open this project folder in a terminal.
3. Copy `.env.example` to `.env`.
4. Put your SMTP settings in `.env`.
5. Run `npm install`.
6. Run `npm start`.
7. Open `http://localhost:3000`.

Windows: double-click `start.bat` after Node.js is installed.

## Online deployment
This project includes `render.yaml` for Render. Create a Render Web Service from this project/repository, then set the SMTP environment variables shown in `.env.example`.
After deployment, open the generated HTTPS URL. Do NOT open `public/index.html` directly.

## Real email
You must connect a real SMTP provider. The project never puts SMTP credentials in browser JavaScript.

## Important
I can prepare the complete deployment package here, but I cannot create an external hosting account, accept its terms, or enter your private hosting/SMTP credentials on your behalf. Once the project is deployed with those credentials, Create Account, email verification, forgot password, and password change use the real backend.
