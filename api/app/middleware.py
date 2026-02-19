import os
import time
import redis
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from urllib.parse import urlparse
import secrets

from .auth import get_current_user
from .db import SessionLocal
from . import models


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limit_per_minute: int) -> None:
        super().__init__(app)
        self.limit_per_minute = limit_per_minute
        redis_url = os.environ.get("REDIS_URL", "redis://redis:6379/0")
        self.redis = redis.Redis.from_url(redis_url)

    def _rate_limit(self, key: str, max_requests: int, window_seconds: int) -> bool:
        now = time.time()
        window_start = now - window_seconds
        pipe = self.redis.pipeline()
        pipe.zremrangebyscore(key, 0, window_start)
        pipe.zcard(key)
        pipe.zadd(key, {str(now): now})
        pipe.expire(key, window_seconds)
        _, count, _, _ = pipe.execute()
        return count < max_requests

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if self.limit_per_minute <= 0:
            return await call_next(request)

        ip = request.client.host if request.client else "unknown"
        if "/auth/" in request.url.path:
            key = f"rl:auth:{ip}"
            allowed = self._rate_limit(key, max_requests=10, window_seconds=60)
        else:
            key = f"rl:api:{ip}"
            allowed = self._rate_limit(key, max_requests=self.limit_per_minute, window_seconds=60)
        if not allowed:
            return Response("Rate limit exceeded", status_code=429)
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


class AuditLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        if os.environ.get("AUDIT_LOGS_ENABLED", "true").lower() != "true":
            return response

        token = request.headers.get("Authorization", "")
        user_id = None
        if not token and request.cookies.get("access_token"):
            token = f"Bearer {request.cookies.get('access_token')}"
        if token.startswith("Bearer "):
            with SessionLocal() as db:
                try:
                    user = get_current_user(token=token.replace("Bearer ", ""), db=db)
                    user_id = user.id
                except Exception:
                    user_id = None

        ip = request.client.host if request.client else "unknown"
        with SessionLocal() as db:
            entry = models.AuditLog(
                user_id=user_id,
                method=request.method,
                path=str(request.url.path),
                status_code=response.status_code,
                ip=ip,
            )
            db.add(entry)
            db.commit()

        return response


class CSRFMiddleware(BaseHTTPMiddleware):
    SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
    EXEMPT_PATHS = {
        "/auth/login",
        "/auth/register",
        "/auth/forgot-password",
        "/auth/reset-password",
        "/auth/rotate-password",
        "/health",
    }

    def __init__(self, app, allowed_origins: list[str] | None = None) -> None:
        super().__init__(app)
        self.allowed_origins = set(allowed_origins or [])

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.method in self.SAFE_METHODS:
            return await call_next(request)

        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        if request.headers.get("X-API-Key"):
            return await call_next(request)

        if not request.cookies.get("access_token"):
            return await call_next(request)

        origin = request.headers.get("origin")
        referer = request.headers.get("referer")

        if origin:
            if origin not in self.allowed_origins:
                return JSONResponse(status_code=403, content={"detail": "CSRF: Origin no permitido"})
        elif referer:
            ref_parsed = urlparse(referer)
            ref_origin = f"{ref_parsed.scheme}://{ref_parsed.netloc}"
            if ref_origin not in self.allowed_origins:
                return JSONResponse(status_code=403, content={"detail": "CSRF: Referer no permitido"})
        else:
            return JSONResponse(status_code=403, content={"detail": "CSRF: Missing Origin header"})

        csrf_cookie = request.cookies.get("csrf_token")
        csrf_header = request.headers.get("X-CSRF-Token")

        if not csrf_cookie or not csrf_header:
            return JSONResponse(status_code=403, content={"detail": "CSRF: Token faltante"})

        if not secrets.compare_digest(csrf_cookie, csrf_header):
            return JSONResponse(status_code=403, content={"detail": "CSRF: Token invalido"})

        return await call_next(request)
