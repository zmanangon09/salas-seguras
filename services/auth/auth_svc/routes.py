"""Rutas públicas y autenticadas de auth (spec §23.4; riesgos 4 y 5)."""

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from auth_svc import accounts, sessions
from shared import audit, ratelimit
from shared.identity import UserIdentity, client_ip, require_gateway, require_user
from shared.passwords import verify_secret_async

router = APIRouter()


class Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


@router.post("/api/auth/login", dependencies=[Depends(require_gateway)])
async def login(body: Credentials, request: Request) -> dict:
    settings, engine = request.app.state.settings, request.app.state.engine
    ip = client_ip(request)
    username = accounts.normalize(body.username)

    limits = [
        (f"user:{username}", settings.login_max_fails),
        (f"ip:{ip}", settings.login_max_fails),
    ]

    async with engine.connect() as conn:
        locked = await ratelimit.any_over(conn, limits, settings.login_window_min)
        user = await accounts.by_username(conn, username)

    if locked:
        audit.emit("warning", "auth.login.locked", actor=f"ip:{ip}", target=username, ip=ip)
        raise HTTPException(
            429,
            "demasiados intentos",
            headers={"Retry-After": str(settings.login_window_min * 60)},
        )

    # Verificación en tiempo constante (con dummy si user es None)
    is_valid = await verify_secret_async(user.password_hash if user else None, body.password)
    if not is_valid:
        async with engine.begin() as conn:
            fails = await ratelimit.record(conn, [k for k, _ in limits], settings.login_window_min)
        audit.emit("warning", "auth.login.fail", actor=f"ip:{ip}", target=username, ip=ip)
        if settings.login_delay_base > 0:
            await asyncio.sleep(min(settings.login_delay_base * 2 ** (fails - 1), 4))
        raise HTTPException(401, "credenciales inválidas")

    # Si la contraseña es válida pero la cuenta está inactiva -> 403
    if user.status != "active":
        audit.emit("warning", "auth.login.inactive", actor=f"ip:{ip}", target=username, ip=ip)
        raise HTTPException(403, "cuenta inactiva")

    async with engine.begin() as conn:
        session_id, expires_at = await sessions.create(conn, settings, user.id)
        roles = await accounts.active_role_names(conn, user.id)

    audit.emit("info", "auth.login.ok", actor=f"user:{username}", ip=ip)
    token = sessions.issue(
        request.app,
        user_id=user.id,
        username=username,
        session_id=session_id,
        roles=roles,
        expires_at=expires_at,
    )
    return sessions.login_body(token, expires_at)


@router.get("/api/auth/profile")
async def profile(who: UserIdentity = Depends(require_user), request: Request = None) -> dict:
    engine = request.app.state.engine
    async with engine.connect() as conn:
        user = await accounts.by_id(conn, who.user_id)
        if user is None:
            raise HTTPException(404, "usuario no encontrado")
        roles = await accounts.active_role_names(conn, who.user_id)
        perms = await accounts.active_permissions(conn, who.user_id)

    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "status": user.status,
        "roles": roles,
        "permissions": sorted(perms),
    }


@router.post("/api/auth/logout", status_code=204)
async def logout(request: Request, who: UserIdentity = Depends(require_user)) -> Response:
    async with request.app.state.engine.begin() as conn:
        await sessions.end(conn, who.session_id, "logout")

    audit.emit("info", "auth.logout", actor=f"user:{who.username}", ip=client_ip(request))
    return Response(status_code=204)
