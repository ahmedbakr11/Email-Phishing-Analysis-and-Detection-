# DefendX (Auth + Phishing Analyzer)

This project has been slimmed down to only what is needed for user registration/login and the phishing email analyzer. All other tools, dashboards, and the Gmail extension have been removed.

## Features
- RSA-encrypted signup/login with JWT access + refresh tokens.
- Phishing email analyzer that accepts `.eml` uploads or raw text and returns a score/verdict with supporting details.
- React/Vite frontend with login, registration, and a protected phishing scan page.
- SQLite dev database (`backend/dev.db`) included for quick local runs.

## Project Structure
- `backend/`: Flask RESTX API (auth + phishing analyzer).
- `frontend/`: React client.
- `keys/`: RSA key material (generated if missing).
- `migrations/`: Existing database migrations (optional for new databases).

## Running Locally
### Backend
```sh
cd backend
python -m venv .venv
.\.venv\Scripts\activate  # or source .venv/bin/activate
pip install flask flask-restx flask-sqlalchemy flask-migrate flask-jwt-extended python-decouple requests beautifulsoup4 tldextract whois cryptography
python -m app.main
```

- API base: `http://localhost:5000/api`
- Endpoints:
  - `POST /auth/signup`
  - `POST /auth/login`
  - `POST /auth/refresh`
  - `GET /auth/public-key`
  - `POST /tools/Phishing-email/text-scan` (JWT required, JSON body with `body`)
  - `POST /tools/Phishing-email/eml-scan` (JWT required, multipart form-data with file field `eml`)

### Frontend
```sh
cd frontend
npm install
npm run dev
```
- Default dev server: `http://localhost:5173`
- Login redirects to the protected phishing analyzer at `/phishing`.

## Notes
- Access and refresh tokens are stored in `localStorage` under `access_token` and `refresh_token`.
- Replace the bundled SQLite DBs if you want a clean database state.
