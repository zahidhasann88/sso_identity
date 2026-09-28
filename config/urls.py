from django.http import JsonResponse
from django.urls import include, path

from identity import views


def service_root(request):
    """Tiny index so `GET /` is useful rather than a 404 in probes."""
    return JsonResponse(
        {
            "service": "sso-identity",
            "description": "Centralized OAuth2/JWT SSO Identity Provider "
                           "(RS256, asymmetric issuance).",
            "endpoints": {
                "register": "/api/auth/register/",
                "login": "/api/auth/login/",
                "refresh": "/api/auth/refresh/",
                "logout": "/api/auth/logout/",
                "introspect": "/api/auth/introspect/",
                "change_password": "/api/auth/password/change/",
                "me": "/api/auth/me/",
                "public_key": "/api/auth/keys/",
                "jwks": "/.well-known/jwks.json",
                "discovery": "/.well-known/openid-configuration",
                "health": "/api/health/",
            },
        }
    )


urlpatterns = [
    path("", service_root, name="service-root"),
    path("api/", include("identity.urls")),
    path(".well-known/jwks.json", views.jwks, name="jwks"),
    path(
        ".well-known/openid-configuration",
        views.openid_configuration,
        name="openid-configuration",
    ),
]
