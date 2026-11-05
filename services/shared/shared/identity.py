"""Identidad propagada por el gateway (spec §4.3). Solo se lee si el llamador verificado es 'gateway'."""

from dataclasses import dataclass

from fastapi import HTTPException, Request
from starlette.requests import HTTPConnection

from shared import audit

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass(frozen=True)
class UserIdentity:
    user_id: str
    username: str
    session_id: str  # sesión de la cuenta (claim sid del JWT)
    perms: frozenset[str]  # los actuales: auth los lee de la BD en cada request


def client_ip(conn: HTTPConnection) -> str | None:
    """IP del cliente original: uvicorn la toma de X-Forwarded-For, que el gateway sobrescribe."""
    return conn.client.host if conn.client else None


async def require_gateway(request: Request) -> None:
    """Rutas públicas: solo el gateway puede llamarlas; un Origin ajeno en las que cambian estado → 403 (CSRF).

    Sin Origin pasa: Postman y curl no lo mandan, y sin cookies no hay CSRF (spec §23.1).
    """
    ip = client_ip(request)
    if request.state.caller != "gateway":
        audit.emit(
            "warning",
            "svc.reject.token",
            actor=f"svc:{request.state.caller}",
            target=request.url.path,
            ip=ip,
        )
        raise HTTPException(403, "no autorizado")
    origin = request.headers.get("origin")
    if (
        request.method in UNSAFE_METHODS
        and origin is not None
        and origin not in request.app.state.settings.allowed_origins
    ):
        audit.emit(
            "warning",
            "http.reject.origin",
            actor=f"ip:{ip}",
            target=request.url.path,
            ip=ip,
            details={"origin": origin},
        )
        raise HTTPException(403, "origen no permitido")


def user_from_headers(conn: HTTPConnection) -> UserIdentity | None:
    """Identidad que puso el gateway. Sin permisos, X-User-Perms no viene (Nginx omite cabeceras vacías).

    Si el llamador verificado no es el gateway, las cabeceras X-User-* se ignoran.
    """
    if getattr(conn.state, "caller", None) != "gateway":
        return None
    headers = conn.headers
    values = (headers.get("x-user-id"), headers.get("x-user-name"), headers.get("x-session-id"))
    if not all(values):
        return None
    perms = frozenset(perm for perm in headers.get("x-user-perms", "").split(",") if perm)
    return UserIdentity(*values, perms)


async def require_user(request: Request) -> UserIdentity:
    await require_gateway(request)
    who = user_from_headers(request)
    if who is None:
        raise HTTPException(401, "no autenticado")
    return who


def require_perm(*perms: str):
    """Dependencia de ruta: el usuario debe tener **todos** los permisos pedidos (spec §9.1)."""

    async def dependency(request: Request) -> UserIdentity:
        who = await require_user(request)
        if not set(perms) <= who.perms:
            ip = client_ip(request)
            audit.emit(
                "warning",
                "perm.denied",
                actor=f"user:{who.username}",
                target=request.url.path,
                ip=ip,
                details={"required": list(perms)},
            )
            raise HTTPException(403, "permiso insuficiente")
        return who

    return dependency
