# Standalone application + PostgreSQL

This version does not use Google Forms.

## What it includes
- Custom red responsive application UI
- POST endpoint for submissions
- PostgreSQL storage
- National ID encrypted with AES-256-GCM before database storage
- Confirmation/reference number
- Password-protected admin area at `/admin`
- Application detail view
- `/bot/bot7` route

## Render setup

Create a **Web Service**, not a Static Site. Render Web Services support Express/Node apps and use the service's public `onrender.com` URL. See Render's Web Service docs.

Build command:
`npm install`

Start command:
`npm start`

Create a Render Postgres database and connect its connection string to the web service as `DATABASE_URL`.

Add these environment variables in Render:
- `DATABASE_URL` = your Render Postgres connection string
- `ADMIN_USER` = a username you choose
- `ADMIN_PASSWORD` = a strong, unique admin password
- `APP_SECRET` = a long random secret
- `ENCRYPTION_KEY` = exactly 64 hexadecimal characters (32 bytes)

Do not put secrets in GitHub.

## Admin
After deployment:
`https://YOUR-SERVICE.onrender.com/admin`

Applicant page:
`https://YOUR-SERVICE.onrender.com/bot/bot7`

## Security note
This app encrypts the national ID field before storing it and does not display the ID in the application list. Because national ID is highly sensitive, use HTTPS, strong admin credentials, least-privilege access, backups/retention controls, and appropriate legal/privacy notices before collecting real applicant data.

Use only branding, claims, and financial-service names you are authorized to use.
