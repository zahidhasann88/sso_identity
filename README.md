# SSO Identity

A login service (single sign-on) built with Django. Users log in once and get a
token; your other apps check that token themselves, without calling this service.

**What it does**

- Register, log in, log out, change password
- Issues signed JWT tokens (access token: 15 min, refresh token: 7 days)
- Logout and password change really cancel old tokens
- Protects against common attacks (brute-force login, stolen/reused tokens, forged tokens)

**Highlights**

- **Stolen refresh tokens are caught.** Each refresh token works only once; if a
  used one shows up again, the whole session is shut down.
- **Signing keys can be rotated with no downtime.** The old key keeps verifying
  existing tokens while the new key signs fresh ones.
- **Race conditions are tested.** Tests fire simultaneous requests (e.g. two
  refreshes of the same token) to prove only one succeeds.
- **Attack simulation script.** `scripts/security_demo.py` runs real attacks
  against the service and checks that every one is blocked.

## How it works

```
  user ──login──▶ SSO Identity ──▶ PostgreSQL
                       │
                       └─ publishes public key at /.well-known/jwks.json
                                    │
  your other apps ◀─────────────────┘  verify tokens with that key
```

Only this service can create tokens. Other apps download the public key once
and use it to check tokens locally.

## Getting started

You need **Python 3.12+** and **PostgreSQL** (or Docker to run Postgres for you).

```bash
pip install -r requirements/dev.txt
cp .env.example .env              # then set DB_PASSWORD and DJANGO_SECRET_KEY in it
docker compose up -d db           # starts Postgres (skip if you have your own)
python manage.py migrate           # also creates signing keys in keys/ on first run
python manage.py runserver
```

To make a secret key, run:

```bash
python -c "import secrets; print(secrets.token_urlsafe(50))"
```

Open http://localhost:8000/api/health/ — if you see `"database":"ok"`, it's running.

## Try it

**Bash / macOS / Linux**

```bash
# Register
curl -X POST http://localhost:8000/api/auth/register/ -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","password":"Xq7!vartan-Spindle42","password_confirm":"Xq7!vartan-Spindle42"}'

# Log in (returns access_token and refresh_token)
curl -X POST http://localhost:8000/api/auth/login/ -H "Content-Type: application/json" \
  -d '{"identifier":"alice","password":"Xq7!vartan-Spindle42"}'

# Who am I?
curl http://localhost:8000/api/auth/me/ -H "Authorization: Bearer <access_token>"
```

**Windows PowerShell**

```powershell
$B = 'http://localhost:8000'
$P = 'Xq7!vartan-Spindle42'

Invoke-RestMethod "$B/api/auth/register/" -Method Post -ContentType 'application/json' `
  -Body (@{ username='alice'; email='alice@example.com'; password=$P; password_confirm=$P } | ConvertTo-Json)

$login = Invoke-RestMethod "$B/api/auth/login/" -Method Post -ContentType 'application/json' `
  -Body (@{ identifier='alice'; password=$P } | ConvertTo-Json)

Invoke-RestMethod "$B/api/auth/me/" -Headers @{ Authorization = "Bearer $($login.tokens.access_token)" }
```

## API endpoints

| Method | Path | What it does |
| ------ | ---- | ------------ |
| POST | `/api/auth/register/` | Create an account |
| POST | `/api/auth/login/` | Log in, get tokens |
| POST | `/api/auth/refresh/` | Get a new access token using the refresh token |
| POST | `/api/auth/logout/` | Log out (one session, or all with `"all_sessions": true`) |
| POST | `/api/auth/password/change/` | Change password (logs out everywhere) |
| POST | `/api/auth/introspect/` | Check if a token is still valid |
| GET | `/api/auth/me/` | Current user's info |
| GET | `/.well-known/jwks.json` | Public key for verifying tokens |
| GET | `/.well-known/openid-configuration` | Discovery info |
| GET | `/api/health/` | Health check |

## Running tests

```bash
python manage.py test identity     # unit and integration tests
python scripts/security_demo.py    # simulates real attacks and checks they fail
python -m ruff check .             # lint
```

Run the two test commands one at a time — they share a temporary database.

Shortcuts for these and other tasks are in the `Makefile` (run `make help`).

## Configuration

All settings live in `.env`. `.env.example` is set up for local development and
shows the value to use in production where it differs.

For production, run `python manage.py check --deploy` — it warns you about
anything that's not set up safely (for example, use Redis for `CACHE_URL` when
running several workers).

## License

MIT — see [LICENSE](LICENSE). To report a security issue, see [SECURITY.md](SECURITY.md).
