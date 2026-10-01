"""Stable JSON error envelope.

Every error response has the shape::

    {"error": {"code": "<stable_machine_code>", "message": "<human text>"}}

Error codes are part of the API contract and never expose internal details
such as whether an organization exists (non-members get ``forbidden`` both
when the org is missing and when they lack access).
"""
from __future__ import annotations

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


class ApiError(Exception):
    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


# Common shortcuts ---------------------------------------------------------

def unauthorized(message: str = "authentication required") -> ApiError:
    return ApiError(401, "unauthorized", message)


def forbidden(message: str = "forbidden") -> ApiError:
    # Deliberately identical wording regardless of org existence/membership.
    return ApiError(403, "forbidden", message)


def not_found(code: str = "not_found", message: str = "not found") -> ApiError:
    return ApiError(404, code, message)


def conflict(code: str, message: str) -> ApiError:
    return ApiError(409, code, message)


def install_exception_handlers(app) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code, "message": exc.message}},
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={"error": {"code": "validation_error", "message": "invalid request"}},
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        # Normalize framework 404/405/etc. into the stable JSON envelope.
        if exc.status_code == 404:
            code, message = "not_found", "not found"
        elif exc.status_code == 405:
            code, message = "method_not_allowed", "method not allowed"
        else:
            code, message = "error", "error"
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": code, "message": message}},
        )

    @app.exception_handler(Exception)
    async def _unexpected(_: Request, exc: Exception) -> JSONResponse:  # pragma: no cover
        # Do not leak internals; never echo tokens or passwords.
        return JSONResponse(
            status_code=500,
            content={"error": {"code": "internal_error", "message": "internal error"}},
        )
