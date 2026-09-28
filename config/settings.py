from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent

try:
    from dotenv import load_dotenv
except ImportError:
    pass
else:
    load_dotenv(BASE_DIR / ".env", override=False)


def env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(name, default)


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError as exc:
        raise ImproperlyConfigured(
            f"{name} must be an integer; got {raw!r}."
        ) from exc


def env_list(name: str, default: str = "") -> list[str]:
    raw = os.environ.get(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


DEBUG = env_bool("DJANGO_DEBUG", False)

SECRET_KEY = env("DJANGO_SECRET_KEY") or ""
if not SECRET_KEY:
    if not DEBUG:
        raise ImproperlyConfigured(
            "DJANGO_SECRET_KEY must be set when DEBUG is False."
        )
    SECRET_KEY = "django-insecure-dev-only-" + os.urandom(16).hex()

ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "*" if DEBUG else "")
if not ALLOWED_HOSTS and not DEBUG:
    raise ImproperlyConfigured("DJANGO_ALLOWED_HOSTS must be set in production.")

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
AUTH_USER_MODEL = "identity.CustomUser"
APPEND_SLASH = True

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "rest_framework",
    "identity",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
    "identity.middleware.SecurityHeadersMiddleware",
    "identity.middleware.RequestIDMiddleware",
]

TEMPLATES: list[dict] = []


def database_config() -> dict:
    """Resolve the ``default`` database from the environment."""
    common = {
        "ENGINE": "django.db.backends.postgresql",
        "CONN_MAX_AGE": env_int("DB_CONN_MAX_AGE", 60),
        "CONN_HEALTH_CHECKS": True,
        "OPTIONS": {"sslmode": env("DB_SSLMODE", "prefer")},
    }

    url = env("DATABASE_URL")
    if url:
        from urllib.parse import unquote, urlparse

        parsed = urlparse(url)
        if parsed.scheme not in {"postgres", "postgresql"}:
            raise ImproperlyConfigured(
                f"DATABASE_URL must be a PostgreSQL URL; got scheme "
                f"{parsed.scheme!r}. This service does not support other engines."
            )
        return {
            **common,
            "NAME": (parsed.path or "/").lstrip("/"),
            "USER": unquote(parsed.username or ""),
            "PASSWORD": unquote(parsed.password or ""),
            "HOST": parsed.hostname or "",
            "PORT": str(parsed.port or ""),
        }

    return {
        **common,
        "NAME": env("DB_NAME", "sso_db"),
        "USER": env("DB_USER", "postgres"),
        "PASSWORD": env("DB_PASSWORD", ""),
        "HOST": env("DB_HOST", "localhost"),
        "PORT": env("DB_PORT", "5432"),
    }


DATABASES = {"default": database_config()}


def argon2_available() -> bool:
    """True when ``argon2-cffi`` (an optional extra) is importable."""
    try:
        import argon2  # noqa: F401
    except ImportError:
        return False
    return True


def password_hashers(with_argon2: bool | None = None) -> list[str]:
    """
    Build ``PASSWORD_HASHERS``, preferring Argon2id when it is installed.

    Django loads the *first* hasher eagerly, so listing Argon2 unconditionally
    is a hard startup error wherever the optional ``argon2-cffi`` is absent.

    ``with_argon2`` is an override for tests; leave it None in real use.
    """
    if with_argon2 is None:
        with_argon2 = argon2_available()

    preferred = ["django.contrib.auth.hashers.Argon2PasswordHasher"] if with_argon2 else []
    return preferred + [
        "django.contrib.auth.hashers.PBKDF2PasswordHasher",
        "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
        "django.contrib.auth.hashers.ScryptPasswordHasher",
    ]


PASSWORD_HASHERS = password_hashers()

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": env_int("PASSWORD_MIN_LENGTH", 12)},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]


LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = False
USE_TZ = True


REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "identity.authentication.JWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "DEFAULT_RENDERER_CLASSES": ("rest_framework.renderers.JSONRenderer",),
    "DEFAULT_PARSER_CLASSES": ("rest_framework.parsers.JSONParser",),
    "DEFAULT_THROTTLE_CLASSES": (),
    "DEFAULT_THROTTLE_RATES": {
        "auth_login": env("THROTTLE_LOGIN", "10/min"),
        "auth_register": env("THROTTLE_REGISTER", "5/min"),
        "auth_refresh": env("THROTTLE_REFRESH", "30/min"),
        "auth_logout": env("THROTTLE_LOGOUT", "20/min"),
        "auth_introspect": env("THROTTLE_INTROSPECT", "60/min"),
        "auth_password_change": env("THROTTLE_PASSWORD_CHANGE", "5/min"),
    },
    "EXCEPTION_HANDLER": "identity.exceptions.rfc7807_exception_handler",
    "UNAUTHENTICATED_USER": "django.contrib.auth.models.AnonymousUser",
    "UNICODE_JSON": False,
}


JWT_ALGORITHM = env("JWT_ALGORITHM", "RS256")
JWT_ISSUER = env("JWT_ISSUER", "https://sso.identity.local")
JWT_AUDIENCE = env_list("JWT_AUDIENCE", "identity-clients")
JWT_LEEWAY_SECONDS = env_int("JWT_LEEWAY_SECONDS", 10)

ACCESS_TOKEN_LIFETIME = timedelta(minutes=env_int("ACCESS_TOKEN_MINUTES", 15))
REFRESH_TOKEN_LIFETIME = timedelta(days=env_int("REFRESH_TOKEN_DAYS", 7))

JWT_ROTATE_REFRESH_TOKENS = env_bool("JWT_ROTATE_REFRESH_TOKENS", True)
JWT_BLACKLIST_AFTER_ROTATION = env_bool("JWT_BLACKLIST_AFTER_ROTATION", True)

JWT_BLACKLIST_BACKEND = env("JWT_BLACKLIST_BACKEND", "db")
REDIS_URL = env("REDIS_URL", "redis://127.0.0.1:6379/0")
JWT_BLACKLIST_REDIS_PREFIX = env("JWT_BLACKLIST_REDIS_PREFIX", "sso:jti:revoked:")

JWT_WARM_KEYRING_ON_BOOT = env_bool("JWT_WARM_KEYRING_ON_BOOT", True)

_PRIVATE_KEY_PATH = env("JWT_PRIVATE_KEY_PATH", str(BASE_DIR / "keys" / "jwt_private.pem"))
JWT_PRIVATE_KEY = env("JWT_PRIVATE_KEY", "") or ""
JWT_PRIVATE_KEY_PASSPHRASE = env("JWT_PRIVATE_KEY_PASSPHRASE", "")

if not JWT_PRIVATE_KEY and _PRIVATE_KEY_PATH and Path(_PRIVATE_KEY_PATH).is_file():
    JWT_PRIVATE_KEY = Path(_PRIVATE_KEY_PATH).read_text(encoding="utf-8")

# Public keys that still verify but no longer sign, so tokens issued before a
# rotation stay valid until they expire. See README "Key rotation".
JWT_ADDITIONAL_PUBLIC_KEYS = env("JWT_ADDITIONAL_PUBLIC_KEYS", "") or ""
JWT_ADDITIONAL_PUBLIC_KEY_PATHS = env_list("JWT_ADDITIONAL_PUBLIC_KEY_PATHS")

for _extra_path in JWT_ADDITIONAL_PUBLIC_KEY_PATHS:
    _candidate = Path(_extra_path)
    if not _candidate.is_file():
        raise ImproperlyConfigured(
            f"JWT_ADDITIONAL_PUBLIC_KEY_PATHS points at {_extra_path!r}, "
            f"which is not a readable file."
        )
    JWT_ADDITIONAL_PUBLIC_KEYS += chr(10) + _candidate.read_text(encoding="utf-8")


if not JWT_PRIVATE_KEY:
    if not DEBUG:
        raise ImproperlyConfigured(
            "No RSA signing key found. Set JWT_PRIVATE_KEY (PEM) or "
            "JWT_PRIVATE_KEY_PATH, e.g. via `python manage.py generate_jwt_keys`."
        )

    from identity.crypto import generate_rsa_keypair

    key_path = Path(_PRIVATE_KEY_PATH)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    private_pem, public_pem = generate_rsa_keypair(2048)
    key_path.write_text(private_pem, encoding="utf-8")
    os.chmod(key_path, 0o600)
    key_path.with_name("jwt_public.pem").write_text(public_pem, encoding="utf-8")
    JWT_PRIVATE_KEY = private_pem


SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "no-referrer"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"

# Opt-in, because forwarding headers are attacker-controlled unless a proxy
# that overwrites them sits in front: otherwise X-Forwarded-Proto fakes HTTPS
# and X-Forwarded-For buys a fresh throttle/lockout bucket per request.
# TRUST_PROXY_COUNT is how many proxies append to X-Forwarded-For.
TRUST_PROXY_HEADERS = env_bool("TRUST_PROXY_HEADERS", False)
TRUST_PROXY_COUNT = max(1, env_int("TRUST_PROXY_COUNT", 1))

if TRUST_PROXY_HEADERS:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# DRF derives the throttle identity from this: 0 pins it to REMOTE_ADDR, N
# reads the Nth-from-last X-Forwarded-For entry. Left unset, DRF trusts the
# client-supplied *leading* entry and every throttle here is bypassable.
REST_FRAMEWORK["NUM_PROXIES"] = TRUST_PROXY_COUNT if TRUST_PROXY_HEADERS else 0

if not DEBUG:
    SECURE_SSL_REDIRECT = env_bool("SECURE_SSL_REDIRECT", True)
    SECURE_HSTS_SECONDS = env_int("SECURE_HSTS_SECONDS", 31_536_000)
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True

LOGIN_FAILURE_LIMIT = env_int("LOGIN_FAILURE_LIMIT", 8)
LOGIN_FAILURE_WINDOW_SECONDS = env_int("LOGIN_FAILURE_WINDOW_SECONDS", 900)

# Throttle and login-failure counters live here, so every process serving
# traffic has to share it. The local-memory default is per-process, which
# multiplies every limit by the worker count; set CACHE_URL in any
# multi-process deployment. identity.checks warns when DEBUG is off and it
# is still local memory.
CACHE_URL = env("CACHE_URL", "") or ""

if CACHE_URL:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": CACHE_URL,
            "KEY_PREFIX": env("CACHE_KEY_PREFIX", "sso"),
        }
    }
else:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "identity-default",
        }
    }


LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "%(asctime)s %(levelname)s [%(name)s] %(message)s",
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
        }
    },
    "root": {"handlers": ["console"], "level": env("LOG_LEVEL", "INFO")},
    "loggers": {
        "identity.security": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "django.request": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
    },
}
