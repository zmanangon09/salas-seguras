"""Rutas internas de auth (spec §23.6): authorization/check para el gateway (riesgos 5 y 16)."""

import json
import re

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from auth_svc import accounts
from shared import audit
from shared.identity import client_ip
from shared.service_auth import allow

router = APIRouter()

SESSION_CHECK = text(
    "SELECT s.id AS sid, s.user_id::text AS user_id, "
    "(s.ended_at IS NOT NULL OR s.expires_at <= now()) AS is_ended, "
    "u.username, u.status AS user_status "
    "FROM user_sessions s "
    "JOIN users u ON u.id = s.user_id "
    "WHERE s.id = CAST(:sid AS uuid) AND s.user_id = CAST(:user AS uuid)"
)

ROUTE_ACTIONS = [
    (re.compile(r"^/api/auth/(profile|logout)(/|$)"), "session"),
    (re.compile(r"^/api/users(/|$)"), "users.manage"),
    (re.compile(r"^/api/roles(/|$)"), "roles.manage"),
    (re.compile(r"^/api/user-roles(/|$)"), "roles.manage"),
    (re.compile(r"^/api/steganography/analyze(/|$)"), "steganography.analyze"),
    (re.compile(r"^/api/steganography/results(/|$)"), "steganography.results.read"),
]


def resolve_action(uri: str) -> str | None:
    """Traduce la URI pedida a la acción correspondiente según spec §23.6."""
    path = uri.split("?")[0]
    for pattern, action in ROUTE_ACTIONS:
        if pattern.search(path):
            return action
    return None


async def parse_json_body(request: Request) -> dict:
    """Extrae datos JSON opcionales del cuerpo de la petición si existe."""
    if "application/json" not in request.headers.get("content-type", ""):
        return {}
    try:
        body_bytes = await request.body()
        return json.loads(body_bytes) if body_bytes else {}
    except Exception:
        return {}


def extract_token(request: Request, body_data: dict) -> str | None:
    """Obtiene el token desde la cabecera Authorization o el cuerpo subject_token."""
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return body_data.get("subject_token")


@router.post("/internal/authorization/check", dependencies=[Depends(allow("gateway"))])
async def check(request: Request) -> JSONResponse:
    ip = client_ip(request)
    body_data = await parse_json_body(request)
    token = extract_token(request, body_data)
    if not token:
        return JSONResponse({"allowed": False, "reason": "invalid_token"}, status_code=401)

    claims = request.app.state.signer.read(token)
    if claims is None:
        return JSONResponse({"allowed": False, "reason": "invalid_token"}, status_code=401)

    user_id, session_id = claims["sub"], claims["sid"]
    async with request.app.state.engine.connect() as conn:
        row = (await conn.execute(SESSION_CHECK, {"sid": session_id, "user": user_id})).first()
        if row is None or row.is_ended:
            return JSONResponse({"allowed": False, "reason": "session_ended"}, status_code=401)
        if row.user_status != "active":
            return JSONResponse({"allowed": False, "reason": "user_inactive"}, status_code=401)
        perms = await accounts.active_permissions(conn, user_id)

    uri = request.headers.get("x-original-uri", "")
    action = resolve_action(uri) if uri else body_data.get("action")
    if not action:
        audit.emit(
            "warning",
            "authz.denied",
            actor=f"user:{row.username}",
            target="unknown",
            ip=ip,
            details={"uri": uri, "reason": "unknown_action"},
        )
        return JSONResponse(
            {
                "subject_id": user_id,
                "action": "unknown",
                "allowed": False,
                "reason": "unknown_action",
            },
            status_code=403,
        )

    allowed = (action == "session") or (action in perms)
    if not allowed:
        audit.emit(
            "warning",
            "authz.denied",
            actor=f"user:{row.username}",
            target=action,
            ip=ip,
            details={"uri": uri, "reason": "no_active_role_grants_permission"},
        )
        return JSONResponse(
            {
                "subject_id": user_id,
                "action": action,
                "allowed": False,
                "reason": "no_active_role_grants_permission",
            },
            status_code=403,
        )

    headers = {"X-User-Id": user_id, "X-User-Name": row.username, "X-Session-Id": session_id}
    if perms:
        headers["X-User-Perms"] = ",".join(sorted(perms))
    reason = "authenticated_session" if action == "session" else "active_role_grants_permission"
    return JSONResponse(
        {"subject_id": user_id, "action": action, "allowed": True, "reason": reason},
        status_code=200,
        headers=headers,
    )
