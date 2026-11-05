"""Sesiones de usuario: revocables y con expiración absoluta (spec §23.3, §23.4, §23.6)."""

import time
from datetime import datetime
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

INSERT = text(
    "INSERT INTO user_sessions (id, user_id, expires_at) "
    "VALUES (CAST(:id AS uuid), CAST(:user AS uuid), now() + make_interval(mins => :ttl_min)) "
    "RETURNING expires_at"
)
END = text(
    "UPDATE user_sessions SET ended_at = now(), end_reason = :reason "
    "WHERE id = CAST(:id AS uuid) AND ended_at IS NULL"
)


async def create(conn: AsyncConnection, settings, user_id: str) -> tuple[str, datetime]:
    """Crea una nueva sesión para el usuario. TTL definido por jwt_ttl_min (spec §23.4)."""
    session_id = str(uuid4())
    params = {"id": session_id, "user": user_id, "ttl_min": settings.jwt_ttl_min}
    expires_at = (await conn.execute(INSERT, params)).scalar_one()
    return session_id, expires_at


async def end(conn: AsyncConnection, session_id: str, reason: str) -> None:
    """Termina la sesión con el motivo especificado ('logout', 'user_inactive', etc.)."""
    await conn.execute(END, {"id": session_id, "reason": reason})


def issue(
    app,
    *,
    user_id: str,
    username: str,
    session_id: str,
    roles: list[str],
    expires_at: datetime,
) -> str:
    """Firma el JWT RS256 con los claims de la sesión (sin set-cookie en parcial 1)."""
    return app.state.signer.issue(
        user_id=user_id,
        username=username,
        session_id=session_id,
        roles=roles,
        expires_at=expires_at,
    )


def login_body(token: str, expires_at: datetime) -> dict:
    """Cuerpo de respuesta para POST /api/auth/login."""
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": max(int(expires_at.timestamp() - time.time()), 0),
    }
