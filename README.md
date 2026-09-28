# SSO Identity

Centralized single-sign-on identity provider for a microservice estate, on
Django 6 + DRF. It issues RS256-signed JWTs that relying parties verify
**offline** from a published JWKS, and backs them with a revocation ledger so
logout, password change and deactivation actually invalidate outstanding tokens.

## Architecture

```
  client ──────▶┌─ sso-identity ─────────────┐──────▶ PostgreSQL
  login/refresh │  holds the private key,    │        users + revocation ledger
                │  issues & revokes tokens   │
                └─────────── publishes ──────┘
                    /.well-known/jwks.json
                             │
  relying party ─────────────┘  verifies locally, never calls back
```

Only this service holds the signing key. Relying parties fetch the public JWK
once and validate locally, so authentication costs them no round-trip. The
trade-off is a bounded revocation staleness window of one access-token lifetime,
with `/api/auth/introspect/` as the escape hatch when a caller needs certainty.

## Token Model

Access tokens live 15 minutes and carry identity, `role`, a role-derived `scope`
and caller-supplied `meta`. Refresh tokens live 7 days, are deliberately
claim-poor (`sub`, `jti`, `sid`, `tv`, `typ`, `role`) so a leaked one discloses
nothing about the user, and are accepted only at `/refresh/` and `/logout/`.
Principals have UUID primary keys, so `sub` exposes no enumerable sequence.

Three identifiers in every token give three revocation granularities:

| Claim | Scope | Revoking it kills |
| ----- | ----- | ----------------- |
| `jti` | one token | that single token |
| `sid` | one login session | every token in that session (access + refresh) |
| `tv`  | the whole user | every token ever issued to that user |

`tv` is a per-user counter stamped into every token, which makes global sign-out
**O(1)**: bump it and every outstanding token for that principal is stale, with
nothing to enumerate and nothing to write per session.

## Revocation

`JWT_BLACKLIST_BACKEND` selects the store; all three implement one interface.

| Backend | Behaviour |
| ------- | --------- |
| `db` (default) | `jti` *is* the primary key, so a check is one indexed point lookup and double-revocation is idempotent by construction |
| `redis` | Entries carry the token's remaining TTL, so they expire exactly when the token would have |
| `chained` | Redis read-through over the table: an outage costs latency, not security |

Rows are prunable once `exp` alone rejects the token
(`manage.py purge_blacklist`), and `manage.py revoke_user_tokens` revokes a
principal out-of-band for incident response.

### Rotation and replay detection

Rotation is on by default: each refresh consumes the presented token and issues a
replacement bound to the same `sid`. Consuming it is a single atomic insert of the
`jti` — the ledger's primary key — so of N simultaneous callers holding the same
refresh token, exactly one can rotate it. Whoever loses that race is replaying a
consumed token, which is indistinguishable from theft and handled as such: the
whole session is revoked.

## Key Rotation

The signing key and the verification keys are configured separately, which makes
rotation a zero-downtime operation — the retired public key keeps verifying while
only the new key signs.

```bash
cp keys/jwt_public.pem keys/jwt_public.previous.pem      # keep the outgoing key
python manage.py generate_jwt_keys --force --size 4096   # new signing key
# JWT_ADDITIONAL_PUBLIC_KEY_PATHS=keys/jwt_public.previous.pem
# restart, wait one ACCESS_TOKEN_MINUTES, then unset it again
```

During the window the JWKS serves both keys, active first, and each token is
verified only against the key its `kid` names — a `kid` being an RFC 7638
thumbprint of the key material, so every replica derives the same one without
coordination. `GET /api/auth/keys/` reports the drain window in `retired_kids`.
Omit the overlap and rotation becomes an immediate global sign-out, which is the
right move if the old key is believed compromised.

## Security

| Concern | Control |
| ------- | ------- |
| `alg: none`, RS256→HS256 confusion | Asymmetric-only allow-list (`RS256`/`RS384`/`RS512`/`PS256`), enforced on the header *before* signature verification; 2048-bit minimum key size |
| Forged or misrouted tokens | RSA signature plus mandatory `iss`, `aud` and `typ`, checked per token class |
| Stolen refresh token | Single-use rotation; a replay revokes the whole session |
| Stolen access token after logout | `sid` revocation checked on every request, `tv` for the whole principal |
| Credential stuffing | Per-endpoint throttles plus a failure-count lockout |
| Throttle evasion via `X-Forwarded-For` | Counters key off the socket address unless a proxy is explicitly trusted, and then off the hop that proxy appended |
| User enumeration | Identical 401 envelope plus a constant-work dummy hash |
| Password cracking | Argon2id (PBKDF2 fallback) and Django's validator chain, 12-character minimum |
| Token leakage via caches | `Cache-Control: no-store` on every `/api/auth/*` response |

Security events go to the `identity.security` logger; `refresh.reuse_detected`
and `login.locked` are the two worth alerting on.

## API

| Method | Path | Auth | Purpose |
| ------ | ---- | ---- | ------- |
| `POST` | `/api/auth/register/` | none (ADMIN for elevated roles) | Create an account |
| `POST` | `/api/auth/login/` | none | Credentials → access + refresh |
| `POST` | `/api/auth/refresh/` | refresh token | New access token + rotated refresh |
| `POST` | `/api/auth/logout/` | refresh token (access token optional) | Revoke one token or all sessions |
| `POST` | `/api/auth/introspect/` | Bearer (own token, or ADMIN for any) | RFC 7662-style token status |
| `POST` | `/api/auth/password/change/` | Bearer | Rotate password, kill all sessions |
| `GET`  | `/api/auth/me/` | Bearer | The authenticated principal |
| `GET`  | `/api/auth/keys/` | none | Structured public-key document |
| `GET`  | `/.well-known/jwks.json` | none | RFC 7517 JWK Set |
| `GET`  | `/.well-known/openid-configuration` | none | Discovery document (OAuth2-shaped; no `id_token` flow) |
| `GET`  | `/api/health/` | none | Liveness/readiness probe |

Every error shares one envelope — `code`, `detail`, `status` and a `request_id`
matching the `X-Request-ID` response header.

## Quick Start

```bash
pip install -r requirements/dev.txt
cp .env.example .env                        # set DB_PASSWORD and DJANGO_SECRET_KEY
docker compose up -d db                     # or point DB_* at your own Postgres
python manage.py generate_jwt_keys --size 4096
python manage.py migrate
python manage.py runserver
```

Configuration is environment-driven: `.env` is loaded at startup, real
environment variables take precedence, and `.env.example` documents every
variable. `DEBUG=1` generates a development keypair on first boot if none exists;
`DEBUG=0` makes a missing signing key, secret key or `ALLOWED_HOSTS` a hard
startup error.

## Production

`python manage.py check --deploy` reports every item below.

- **Point `CACHE_URL` at Redis.** Throttle and login-lockout counters live in the
  cache, and the local-memory default is per-process — N gunicorn workers
  multiply every limit by N (`identity.W001`).
- **Only trust proxy headers behind a proxy that overwrites them**
  (`TRUST_PROXY_HEADERS`, off by default), or a client can fake HTTPS and pick a
  fresh rate-limit bucket per request. It is required when TLS terminates at a
  proxy, otherwise `SECURE_SSL_REDIRECT` loops (`identity.W003`).
- **Prefer durable revocation.** `JWT_BLACKLIST_BACKEND=redis` un-revokes every
  unexpired token on a flush or failover; `chained` keeps the database as the
  record of truth (`identity.W002`).
- **Leave rotation consuming tokens.** `JWT_BLACKLIST_AFTER_ROTATION=0` never
  consumes the old refresh token, which removes replay detection entirely
  (`identity.W004`).

The container image runs as a non-root user and holds no key material.
`/api/health/` serves liveness and readiness, reporting `503` when the database
or the signing key is unavailable.

## Testing

```bash
python manage.py test identity      # 199 unit/integration tests
python scripts/security_demo.py     # 38-check live attack harness
python -m ruff check .              # lint
python manage.py check --deploy     # production configuration review
pip-audit -r requirements/prod.txt  # dependency advisories
```

The harness drives the full lifecycle against a throwaway database and asserts
each control holds, exiting `0` when every check passes, `1` on a failed check and
`2` when it could not complete. Both test commands use the same scratch database,
so run them sequentially. The suite deliberately covers the failures that only
appear under concurrency — several simultaneous refreshes of one token, and a
registration that loses a uniqueness race — which a sequential test never shows.

## License

MIT — see [LICENSE](LICENSE). Security reporting: [SECURITY.md](SECURITY.md).
