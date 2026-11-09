# Dr. Kalyan_Kharde_Patil – public appointment website (Node.js + PostgreSQL)

Patients register and log in, request appointments, and the admin approves or cancels them. Data lives in PostgreSQL, so everyone sees the same live data.

## Environment variables (set on Render / Railway)
- `DATABASE_URL`  – PostgreSQL connection string (from the host's Postgres add-on)
- `SECRET`        – any long random text (keeps logins valid across restarts)
- `ADMIN_PASSWORD` – the admin password. Choose a NEW one: the demo page exposed the old one.
- `ADMIN_NAME`    – optional, default `Kalyan_Kharde_Patil`

## Deploy on Render
1. Upload this folder to a GitHub repository.
2. Render > New > PostgreSQL. Copy its Internal Database URL.
3. Render > New > Web Service > pick the repo. Build command `npm install`, start command `npm start`.
4. Add the environment variables above, then deploy. Open the `.onrender.com` link.

## Deploy on Railway
1. Upload this folder to GitHub. Railway > New Project > Deploy from GitHub repo.
2. Add a PostgreSQL service. In the web service > Variables, add `DATABASE_URL` = `${{Postgres.DATABASE_URL}}`, `SECRET`, `ADMIN_PASSWORD`.
3. Settings > Networking > Generate Domain.

## Run locally
`npm install` then `DATABASE_URL=postgres://user:pass@localhost:5432/db ADMIN_PASSWORD=YourPass@123 node server.js` and open http://localhost:3000

## Before real patients use it
- "Forgot password" only checks mobile no + email id. Replace it with an email or SMS OTP.
- Patient names and ages are health-related: add a privacy note, use HTTPS only (Render/Railway do), and back up the database.
- Check the host's current free-plan limits (sleeping servers, database expiry).
