"""Autenticación servicio a servicio (R16, spec §4.3): X-Service-Token + allowlist por ruta."""

import hmac
from dataclasses import dataclass

from fastapi import HTTPException, Request
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.websockets import WebSocketClose

from shared import audit
from shared.crypto import sha256
from shared.identity import client_ip
from shared.secrets import secrets_dir

TOKEN_HEADER = "X-Service-Token"  # noqa: S105 — es el nombre de la cabecera, no un secreto


@dataclass(frozen=True)
class ServiceAuth:
    name: str  # servicio dueño
    callers: dict[str, bytes]  # nombre → SHA-256 del token de cada llamador permitido

    @classmethod
    def from_secrets(cls, name: str) -> "ServiceAuth":
        callers = {
            path.name.removeprefix("svc_hash_"): bytes.fromhex(
                path.read_text(encoding="utf-8").strip()
            )
            for path in secrets_dir().glob("svc_hash_*")
        }
        if not callers:
            raise RuntimeError("secreto requerido ausente: svc_hash_* (llamadores permitidos)")
        return cls(name, callers)

    def identify(self, presented: str | None) -> str | None:
        """Nombre del llamador cuyo hash coincide (comparación en tiempo constante) o None."""
        if not presented:
            return None
        digest = sha256(presented.encode())
        found = None
        for name, expected in self.callers.items():
            if hmac.compare_digest(digest, expected):
                found = name
        return found


class ServiceTokenMiddleware:
    """Exige X-Service-Token válido en toda petición HTTP y websocket salvo GET /health."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        exempt = scope["type"] == "lifespan" or (
            scope["type"] == "http" and scope["path"] == "/health" and scope["method"] == "GET"
        )
        if exempt:
            await self.app(scope, receive, send)
            return
        caller = scope["app"].state.service_auth.identify(Headers(scope=scope).get(TOKEN_HEADER))
        if caller is None:
            client = scope.get("client")
            audit.emit(
                "warning",
                "svc.reject.token",
                actor="svc:desconocido",
                target=scope["path"],
                ip=client[0] if client else None,
            )
            if scope["type"] == "http":
                reject = JSONResponse({"error": "no autorizado"}, status_code=401)
            else:  # websocket: 1008 = violación de política
                reject = WebSocketClose(code=1008)
            await reject(scope, receive, send)
            return
        scope.setdefault("state", {})["caller"] = caller
        await self.app(scope, receive, send)


def allow(*callers: str):
    """Dependencia de ruta interna: el llamador verificado debe estar en la allowlist."""

    async def dependency(request: Request) -> str:
        caller = request.state.caller
        if caller not in callers:
            audit.emit(
                "warning",
                "svc.reject.token",
                actor=f"svc:{caller}",
                target=request.url.path,
                ip=client_ip(request),
            )
            raise HTTPException(403, "no autorizado")
        return caller

    return dependency
