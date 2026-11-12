"""Pure-ASGI middleware: request IDs, security headers, hard body-size cap."""
import uuid

from starlette.datastructures import Headers, MutableHeaders
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse

SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Cross-Origin-Resource-Policy": "same-origin",
}

_CODES = {400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found",
          405: "method_not_allowed", 409: "conflict", 413: "payload_too_large",
          422: "validation_error", 429: "rate_limited", 500: "internal_error"}


def error_payload(status: int, message: str, request_id: str, issues=None) -> dict:
    err = {"code": _CODES.get(status, "error"), "message": message, "request_id": request_id}
    if issues:
        err["issues"] = issues
    return {"error": err}


class SecurityMiddleware:
    def __init__(self, app, max_body_bytes: int):
        self.app = app
        self.max_body = max_body_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        rid = uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = rid

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                h = MutableHeaders(scope=message)
                for k, v in SECURITY_HEADERS.items():
                    h[k] = v
                h["X-Request-ID"] = rid
            await send(message)

        # Fast reject on declared size
        cl = Headers(scope=scope).get("content-length")
        if cl is not None:
            status = None
            if not cl.isdigit():
                status, msg = 400, "Invalid Content-Length"
            elif int(cl) > self.max_body:
                status, msg = 413, "Request body too large"
            if status:
                resp = JSONResponse(error_payload(status, msg, rid), status_code=status)
                await resp(scope, receive, send_wrapper)
                return

        # Enforce on bytes actually received (covers chunked / lying clients)
        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body:
                    raise HTTPException(413, "Request body too large")
            return message

        await self.app(scope, limited_receive, send_wrapper)
