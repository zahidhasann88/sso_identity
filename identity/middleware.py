from __future__ import annotations

import uuid


class RequestIDMiddleware:
    """
    Attach/propagate an ``X-Request-ID`` so an auth failure in a client log
    can be tied to the exact server-side decision that produced it.
    """

    header = "HTTP_X_REQUEST_ID"

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        incoming = request.META.get(self.header, "")
        request_id = incoming if 0 < len(incoming) <= 64 and incoming.isprintable() \
            else uuid.uuid4().hex
        request.request_id = request_id
        response = self.get_response(request)
        response["X-Request-ID"] = request_id
        return response


class SecurityHeadersMiddleware:
    """
    Headers appropriate for a pure JSON API.

    A restrictive CSP plus ``no-store`` matters here because responses carry
    bearer tokens: no proxy, browser or bfcache should ever retain them.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; "
            "form-action 'none'",
        )
        response.setdefault("X-Content-Type-Options", "nosniff")
        response.setdefault("Referrer-Policy", "no-referrer")
        response.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )
        if request.path.startswith("/api/auth/"):
            response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response["Pragma"] = "no-cache"
        return response
