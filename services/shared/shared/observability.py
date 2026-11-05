"""Correlación de peticiones y registros JSON (spec §21.1; RNF-19)."""

import json
import logging
import re
import time
from contextvars import ContextVar
from uuid import uuid4

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from shared.secrets import env

REQUEST_HEADER = "X-Request-ID"
REQUEST_ID: ContextVar[str | None] = ContextVar("request_id", default=None)
VALID_ID = re.compile(r"[A-Za-z0-9-]{8,64}")
log = logging.getLogger("http")


class JsonFormatter(logging.Formatter):
    """Una línea JSON por registro: ts, service, level, request_id, logger, msg y, si los hay,
    los campos de la petición (method, path, status, ms) o el evento de seguridad (event)."""

    def __init__(self, service: str) -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "service": self.service,
            "level": record.levelname.lower(),
            "request_id": REQUEST_ID.get(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        fields = ("method", "path", "status", "ms", "event")
        entry.update({k: getattr(record, k) for k in fields if hasattr(record, k)})
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False, default=str)


def configure_logging(service: str) -> None:
    """Solo con LOG_FORMAT=json (en los contenedores). Las líneas de arranque de uvicorn siguen en texto."""
    if env("LOG_FORMAT", "") != "json":
        return
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter(service))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.INFO)


class RequestContextMiddleware:
    """ASGI puro (no BaseHTTPMiddleware). Va como el más externo."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        presented = Headers(scope=scope).get(REQUEST_HEADER, "")
        token = REQUEST_ID.set(presented if VALID_ID.fullmatch(presented) else uuid4().hex)
        started, status = time.perf_counter(), 500

        async def capture(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, capture)
        except Exception:
            # Aquí REQUEST_ID sigue vigente; el handler de errores 500 corre después del reset.
            log.exception("error no controlado en %s", scope["path"])
            raise
        finally:
            if scope["path"] != "/health":
                log.info(
                    "request",
                    extra={
                        "method": scope["method"],
                        # sin query string: ahí podrían viajar datos sensibles
                        "path": scope["path"],
                        "status": status,
                        "ms": round((time.perf_counter() - started) * 1000),
                    },
                )
            REQUEST_ID.reset(token)
