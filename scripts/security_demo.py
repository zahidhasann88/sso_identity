#!/usr/bin/env python
"""
Live security verification harness.

Runs the full SSO lifecycle against a throwaway database and prints a
pass/fail matrix covering asymmetric verification (tokens signed with the
private key are verified using only the published JWKS) and revocation
(a blacklisted token is refused on every protected route).

    python scripts/security_demo.py [--no-color]

Exit codes:

    0   every check passed
    1   at least one security check FAILED - treat as a build breaker
    2   the harness itself could not complete (database setup, or an
        unexpected exception mid-run). This is not a security verdict.

Cleanup trouble - a scratch database that will not drop, say - is reported
loudly but never changes the verdict.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import traceback
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
os.environ.setdefault("DJANGO_DEBUG", "1")

import django  # noqa: E402

django.setup()

import jwt  # noqa: E402
from django.conf import settings as dj_settings  # noqa: E402
from django.test import override_settings  # noqa: E402
from django.test.runner import DiscoverRunner  # noqa: E402
from django.test.utils import setup_test_environment, teardown_test_environment  # noqa: E402
from rest_framework.test import APIClient  # noqa: E402

from identity.crypto import keyring  # noqa: E402
from identity.models import BlacklistedToken  # noqa: E402

PASSWORD = "Xq7!vartan-Spindle42"

TTL_TOLERANCE_SECONDS = 5


def _use_colour() -> bool:
    """
    ANSI escapes only when a human is watching.

    Unconditional colour makes redirected output look binary to tools like
    grep, which is when an operator most needs to read it. Honours NO_COLOR.
    """
    if "--no-color" in sys.argv or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


if _use_colour():
    GREEN, RED, YELLOW, BOLD, RESET = (
        "\033[92m", "\033[91m", "\033[93m", "\033[1m", "\033[0m"
    )
else:
    GREEN = RED = YELLOW = BOLD = RESET = ""

results: list[tuple[str, bool, str]] = []


def check(label: str, condition: bool, note: str = "") -> bool:
    results.append((label, bool(condition), note))
    icon = f"{GREEN}PASS{RESET}" if condition else f"{RED}FAIL{RESET}"
    print(f"  [{icon}] {label}" + (f"  -> {note}" if note else ""))
    return bool(condition)


def section(title: str) -> None:
    print(f"\n{BOLD}{title}{RESET}\n" + "-" * len(title))


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def run() -> int:
    client = APIClient()

    section("1. Registration — hashing and validation")

    registration = client.post(
        "/api/auth/register/",
        {
            "username": "demo_user",
            "email": "demo_user@example.com",
            "password": PASSWORD,
            "password_confirm": PASSWORD,
            "metadata": {"tenant": "acme"},
        },
        format="json",
    )
    check("account created (HTTP 201)", registration.status_code == 201,
          f"status={registration.status_code}")

    from django.contrib.auth import get_user_model

    user = get_user_model().objects.get(username="demo_user")
    check("password stored as a salted hash, not plaintext",
          user.password != PASSWORD and user.password.startswith(
              ("pbkdf2_", "argon2", "scrypt")),
          user.password.split("$")[0])
    check("plaintext password absent from the response body",
          PASSWORD not in registration.content.decode())

    weak = client.post(
        "/api/auth/register/",
        {"username": "weakling", "email": "w@example.com",
         "password": "password123", "password_confirm": "password123"},
        format="json",
    )
    check("weak password rejected (HTTP 400)", weak.status_code == 400)

    escalation = client.post(
        "/api/auth/register/",
        {"username": "sneaky", "email": "s@example.com", "password": PASSWORD,
         "password_confirm": PASSWORD, "system_role": "ADMIN"},
        format="json",
    )
    check("anonymous privilege escalation to ADMIN blocked",
          escalation.status_code == 400)

    section("2. Login — asymmetric token issuance")

    login = client.post(
        "/api/auth/login/",
        {"identifier": "demo_user", "password": PASSWORD},
        format="json",
    )
    check("login succeeded (HTTP 200)", login.status_code == 200)
    tokens = login.json()["tokens"]
    access, refresh = tokens["access_token"], tokens["refresh_token"]

    def ttl_ok(reported: int, configured: int) -> bool:
        return configured - TTL_TOLERANCE_SECONDS <= reported <= configured

    access_ttl = int(dj_settings.ACCESS_TOKEN_LIFETIME.total_seconds())
    refresh_ttl = int(dj_settings.REFRESH_TOKEN_LIFETIME.total_seconds())

    check(f"access token TTL is {access_ttl}s as configured",
          ttl_ok(tokens["expires_in"], access_ttl),
          f"{tokens['expires_in']}s")
    check(f"refresh token TTL is {refresh_ttl}s as configured",
          ttl_ok(tokens["refresh_expires_in"], refresh_ttl),
          f"{tokens['refresh_expires_in']}s")

    header = jwt.get_unverified_header(access)
    check("header advertises RS256 + kid", header["alg"] == "RS256" and "kid" in header,
          f"kid={header.get('kid', '')[:16]}...")

    bad_login = client.post(
        "/api/auth/login/",
        {"identifier": "demo_user", "password": "wrong-password-xyz"},
        format="json",
    )
    check("wrong password rejected (HTTP 401)", bad_login.status_code == 401)

    section("3. Asymmetric decoding loop — verify with the PUBLIC key only")

    jwks = client.get("/.well-known/jwks.json").json()
    jwk = jwks["keys"][0]
    check("JWKS published with exactly one RSA verification key",
          len(jwks["keys"]) == 1 and jwk["kty"] == "RSA")
    check("JWKS contains no private parameters",
          not any(param in jwk for param in ("d", "p", "q", "dp", "dq", "qi")))

    verification_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
    claims = jwt.decode(
        access,
        verification_key,
        algorithms=["RS256"],
        audience=dj_settings.JWT_AUDIENCE,
        issuer=dj_settings.JWT_ISSUER,
    )
    check("relying party verified the token offline using only the JWKS",
          claims["sub"] == str(user.pk),
          f"sub={claims['sub'][:8]}... role={claims['role']}")
    check("every mandatory claim present",
          all(c in claims for c in
              ("iss", "sub", "aud", "iat", "nbf", "exp", "jti", "typ", "sid", "tv")))

    pem_doc = client.get("/api/auth/keys/").json()
    check("PEM distribution endpoint exposes public key only",
          "BEGIN PUBLIC KEY" in pem_doc["public_key_pem"]
          and "PRIVATE" not in pem_doc["public_key_pem"])

    section("4. Forgery attempts — all must be refused")

    payload = dict(claims)

    none_token = (
        f"{b64(json.dumps({'alg': 'none', 'typ': 'JWT'}).encode())}."
        f"{b64(json.dumps(payload).encode())}."
    )
    r = client.get("/api/auth/me/", HTTP_AUTHORIZATION=f"Bearer {none_token}")
    check("alg:none downgrade rejected", r.status_code == 401,
          r.json()["error"]["code"])

    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps(payload).encode())
    sig = b64(hmac.new(keyring().public_pem().encode(),
                       f"{head}.{body}".encode(), hashlib.sha256).digest())
    r = client.get("/api/auth/me/", HTTP_AUTHORIZATION=f"Bearer {head}.{body}.{sig}")
    check("RS256->HS256 key-confusion attack rejected", r.status_code == 401,
          r.json()["error"]["code"])

    header_b64, _, signature_b64 = access.split(".")
    tampered_claims = dict(claims, role="ADMIN", scope="identity:admin")
    r = client.get(
        "/api/auth/me/",
        HTTP_AUTHORIZATION=(
            f"Bearer {header_b64}."
            f"{b64(json.dumps(tampered_claims).encode())}.{signature_b64}"
        ),
    )
    check("tampered role claim rejected (signature mismatch)", r.status_code == 401,
          r.json()["error"]["code"])

    r = client.get("/api/auth/me/", HTTP_AUTHORIZATION=f"Bearer {refresh}")
    check("refresh token refused as an access credential", r.status_code == 401,
          r.json()["error"]["code"])

    section("5. Protected route + rotation")

    r = client.get("/api/auth/me/", HTTP_AUTHORIZATION=f"Bearer {access}")
    check("valid access token admitted (HTTP 200)", r.status_code == 200)

    rotated = client.post("/api/auth/refresh/", {"refresh": refresh}, format="json")
    check("refresh issued a new access token", rotated.status_code == 200)
    rotated_body = rotated.json()
    check("session id preserved across rotation",
          rotated_body["session_id"] == tokens["session_id"])
    check("refresh token itself was rotated",
          rotated_body["refresh_token"] != refresh)

    replay = client.post("/api/auth/refresh/", {"refresh": refresh}, format="json")
    check("replay of the consumed refresh token rejected",
          replay.status_code == 401, replay.json()["error"]["code"])

    section("6. Blacklist — revoked payloads are refused everywhere")

    fresh = client.post(
        "/api/auth/login/", {"identifier": "demo_user", "password": PASSWORD},
        format="json",
    ).json()["tokens"]

    r = client.get("/api/auth/me/", HTTP_AUTHORIZATION=f"Bearer {fresh['access_token']}")
    check("new session works before logout", r.status_code == 200)

    logout = client.post(
        "/api/auth/logout/", {"refresh": fresh["refresh_token"]}, format="json"
    )
    check("logout accepted (HTTP 200)", logout.status_code == 200)
    check("jti persisted in the BlacklistedToken ledger",
          BlacklistedToken.objects.filter(pk=fresh["refresh_jti"]).exists(),
          f"rows={BlacklistedToken.objects.count()}")

    r = client.get("/api/auth/me/", HTTP_AUTHORIZATION=f"Bearer {fresh['access_token']}")
    check("BLACKLISTED access token rejected on a protected route",
          r.status_code == 401, r.json()["error"]["code"])

    r = client.post(
        "/api/auth/refresh/", {"refresh": fresh["refresh_token"]}, format="json"
    )
    check("BLACKLISTED refresh token cannot mint new tokens",
          r.status_code == 401, r.json()["error"]["code"])

    again = client.post(
        "/api/auth/logout/", {"refresh": fresh["refresh_token"]}, format="json"
    )
    check("logout is idempotent",
          again.status_code == 200 and again.json()["already_revoked"] is True)

    section("7. Log out everywhere")

    session_a = client.post(
        "/api/auth/login/", {"identifier": "demo_user", "password": PASSWORD},
        format="json",
    ).json()["tokens"]
    session_b = client.post(
        "/api/auth/login/", {"identifier": "demo_user", "password": PASSWORD},
        format="json",
    ).json()["tokens"]

    everywhere = client.post(
        "/api/auth/logout/",
        {"refresh": session_a["refresh_token"], "all_sessions": True},
        format="json",
    )
    check("global sign-out accepted", everywhere.status_code == 200,
          f"token_version={everywhere.json()['token_version']}")

    a = client.get("/api/auth/me/",
                   HTTP_AUTHORIZATION=f"Bearer {session_a['access_token']}")
    b = client.get("/api/auth/me/",
                   HTTP_AUTHORIZATION=f"Bearer {session_b['access_token']}")
    check("session A killed", a.status_code == 401, a.json()["error"]["code"])
    check("session B (a different device) killed too",
          b.status_code == 401, b.json()["error"]["code"])

    section("8. Introspection is scoped to the token's own subject")

    intruder_pw = PASSWORD
    client.post(
        "/api/auth/register/",
        {"username": "intruder", "email": "intruder@example.com",
         "password": intruder_pw, "password_confirm": intruder_pw},
        format="json",
    )
    intruder = client.post(
        "/api/auth/login/",
        {"identifier": "intruder", "password": intruder_pw},
        format="json",
    ).json()["tokens"]

    victim = client.post(
        "/api/auth/login/", {"identifier": "demo_user", "password": PASSWORD},
        format="json",
    ).json()["tokens"]

    cross = client.post(
        "/api/auth/introspect/",
        {"token": victim["access_token"]},
        format="json",
        HTTP_AUTHORIZATION=f"Bearer {intruder['access_token']}",
    )
    check("introspecting another user's token refused",
          cross.status_code == 403, cross.json()["error"]["code"])
    check("the refusal discloses nothing about the token",
          "identity:read" not in cross.content.decode())

    own = client.post(
        "/api/auth/introspect/",
        {"token": intruder["access_token"]},
        format="json",
        HTTP_AUTHORIZATION=f"Bearer {intruder['access_token']}",
    )
    check("introspecting one's own token still works",
          own.status_code == 200 and own.json()["active"] is True)

    section("9. Abuse counters cannot be reset by the caller")

    # Clear the cache first: this section is about the lockout counter, not the
    # request throttle that shares the same store.
    from django.core.cache import cache

    cache.clear()

    # The lockout key derives from the socket address unless a proxy is trusted,
    # so a forged X-Forwarded-For must not buy new attempts. Pinned off here
    # because that is the shipped default, and with it on the header would be
    # legitimately meaningful — there is no real proxy to model.
    limit = int(dj_settings.LOGIN_FAILURE_LIMIT)
    with override_settings(TRUST_PROXY_HEADERS=False):
        for attempt in range(limit):
            client.post(
                "/api/auth/login/",
                {"identifier": "demo_user", "password": "wrong-password-xyz"},
                format="json",
                HTTP_X_FORWARDED_FOR=f"10.0.0.{attempt % 250}",
            )

        locked = client.post(
            "/api/auth/login/",
            {"identifier": "demo_user", "password": PASSWORD},
            format="json",
            HTTP_X_FORWARDED_FOR="10.99.99.99",
        )
    # Assert the lockout code, not just 429: the request throttle also answers
    # 429 and would make this pass for the wrong reason.
    locked_code = locked.json().get("error", {}).get("code")
    check("rotating X-Forwarded-For did not earn fresh login attempts",
          locked.status_code == 429 and locked_code == "too_many_failed_attempts",
          f"status={locked.status_code} code={locked_code} after {limit} failures")
    check("lockout response tells the client when to retry",
          "Retry-After" in locked)

    section("10. Summary")
    return summarise()


def summarise() -> int:
    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    colour = GREEN if passed == total else RED
    print(f"\n  {colour}{BOLD}{passed}/{total} security checks passed{RESET}")
    if passed != total:
        print(f"  {RED}Failed checks:{RESET}")
        for label, ok, note in results:
            if not ok:
                print(f"    - {label} ({note})")
    return 0 if passed == total else 1


HARNESS_ERROR = 2


def main() -> int:
    """
    Drive the harness, keeping its three outcomes strictly apart.

    The verdict comes from the checks alone: failing to build or drop the
    scratch database is housekeeping, and reporting that as a security failure
    would be misleading in CI.
    """
    banner = f"{BOLD}SSO Identity - security verification harness{RESET}"

    setup_test_environment()
    runner = DiscoverRunner(verbosity=0, interactive=False)

    try:
        old_config = runner.setup_databases()
    except Exception:
        teardown_test_environment()
        print(banner)
        print(f"{RED}{BOLD}Could not create the throwaway test database.{RESET}")
        print(
            f"{YELLOW}No checks ran, so this is not a security result. Check that "
            f"the database in DATABASES['default'] is reachable and that the user "
            f"is allowed to CREATE DATABASE.{RESET}"
        )
        traceback.print_exc()
        return HARNESS_ERROR

    verdict = HARNESS_ERROR
    try:
        db = dj_settings.DATABASES["default"]
        print(banner)
        print(f"{YELLOW}Running against an isolated test database.{RESET}")
        print(
            f"{YELLOW}engine={db['ENGINE'].rsplit('.', 1)[-1]} "
            f"host={db.get('HOST') or 'local'}:{db.get('PORT') or ''} "
            f"issuer={dj_settings.JWT_ISSUER}{RESET}"
        )
        verdict = run()
    except Exception:
        print(f"{RED}{BOLD}The harness crashed before it finished.{RESET}")
        traceback.print_exc()
        summarise()
        print(
            f"{YELLOW}Exiting {HARNESS_ERROR} (harness error): the tally above is "
            f"incomplete and proves nothing about the checks never reached.{RESET}"
        )
        verdict = HARNESS_ERROR
    finally:
        try:
            runner.teardown_databases(old_config)
        except Exception:
            print(
                f"{YELLOW}Warning: the throwaway test database could not be "
                f"dropped. This does not affect the verdict above, but it may "
                f"need removing by hand before the next run.{RESET}"
            )
            traceback.print_exc()
        try:
            teardown_test_environment()
        except Exception:
            print(f"{YELLOW}Warning: test environment teardown failed.{RESET}")
            traceback.print_exc()
        sys.stdout.flush()

    return verdict


if __name__ == "__main__":
    raise SystemExit(main())
