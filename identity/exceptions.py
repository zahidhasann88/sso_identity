from __future__ import annotations

from rest_framework.views import exception_handler as drf_exception_handler

_DEFAULT_CODES = {
    400: "bad_request",
    401: "authentication_failed",
    403: "permission_denied",
    404: "not_found",
    405: "method_not_allowed",
    406: "not_acceptable",
    415: "unsupported_media_type",
    429: "throttled",
    500: "server_error",
}


def _normalize(data, status_code: int) -> tuple[str, str, dict]:
    """Collapse DRF's several error shapes into (code, detail, fields)."""
    code = _DEFAULT_CODES.get(status_code, "error")
    detail = "Request could not be processed."
    fields: dict = {}

    if isinstance(data, dict):
        raw_detail = data.get("detail")
        if isinstance(raw_detail, dict):
            # AuthenticationFailed({"detail": {"code": ..., "detail": ...}})
            code = str(raw_detail.get("code", code))
            detail = str(raw_detail.get("detail", detail))
        elif isinstance(data.get("code"), str) and isinstance(raw_detail, str):
            # AuthenticationFailed({"code": ..., "detail": ...}) — DRF flattens
            # the mapping onto response.data, so the code sits at the top level.
            code = data["code"]
            detail = raw_detail
            fields = {k: v for k, v in data.items() if k not in {"code", "detail"}}
        elif raw_detail is not None:
            detail = str(raw_detail)
            code = str(getattr(raw_detail, "code", None) or code)
            fields = {k: v for k, v in data.items() if k != "detail"}
        else:
            explicit_code = data.get("code")
            if explicit_code and isinstance(explicit_code, str):
                code = explicit_code
                detail = str(data.get("message") or data.get("error") or detail)
                fields = {
                    k: v for k, v in data.items() if k not in {"code", "message", "error"}
                }
            else:
                fields = dict(data)
                detail = "Validation failed." if status_code == 400 else detail
                if status_code == 400:
                    code = "validation_error"
    elif isinstance(data, list):
        fields = {"non_field_errors": data}
        detail = "Validation failed."
        code = "validation_error"
    elif data is not None:
        detail = str(data)

    return code, detail, fields


def rfc7807_exception_handler(exc, context):
    response = drf_exception_handler(exc, context)
    if response is None:
        return None

    code, detail, fields = _normalize(response.data, response.status_code)

    body = {
        "error": {
            "code": code,
            "detail": detail,
            "status": response.status_code,
        }
    }
    if fields:
        body["error"]["fields"] = fields

    request = context.get("request")
    request_id = getattr(request, "request_id", None) if request else None
    if request_id:
        body["error"]["request_id"] = request_id

    response.data = body
    return response
