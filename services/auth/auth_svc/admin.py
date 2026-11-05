"""Administración de usuarios, roles y asignaciones N:M (spec §23.3, §23.4; R5)."""

from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from auth_svc import accounts
from shared import audit
from shared.identity import UserIdentity, client_ip, require_perm
from shared.passwords import hash_secret_async

router = APIRouter()
LAST_ADMIN_LOCK = 4201  # pg_advisory_xact_lock: protección ante carreras de último admin
ADMIN_PERMISSIONS = frozenset({"users.manage", "roles.manage"})

USERS_LIST_QUERY = text("""
    SELECT 
        CAST(u.id AS text) AS id,
        u.username,
        u.email,
        u.status,
        u.created_at,
        u.updated_at,
        COALESCE(
            json_agg(
                json_build_object(
                    'assignment_id', CAST(ur.id AS text),
                    'role_id', CAST(r.id AS text),
                    'name', r.name
                ) ORDER BY r.name
            ) FILTER (WHERE ur.id IS NOT NULL),
            '[]'::json
        ) AS roles
    FROM users u
    LEFT JOIN user_roles ur ON ur.user_id = u.id
    LEFT JOIN roles r ON r.id = ur.role_id
    GROUP BY u.id
    ORDER BY u.created_at ASC
    LIMIT 200
""")

ROLES_LIST_QUERY = text("""
    SELECT 
        CAST(r.id AS text) AS id,
        r.name,
        r.description,
        r.status,
        r.builtin,
        r.created_at,
        r.updated_at,
        COALESCE(
            array_agg(rp.permission ORDER BY rp.permission) FILTER (WHERE rp.permission IS NOT NULL),
            ARRAY[]::text[]
        ) AS permissions
    FROM roles r
    LEFT JOIN role_permissions rp ON rp.role_id = r.id
    GROUP BY r.id
    ORDER BY r.name
""")


class UserCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=32)
    email: str = Field(max_length=254)
    password: str = Field(min_length=12)


class UserPatchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str | None = Field(default=None, max_length=254)
    status: str | None = Field(default=None, pattern=r"^(active|inactive)$")


class RoleCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,31}$")
    description: str = Field(default="", max_length=200)
    permissions: list[str] = Field(default_factory=list, max_length=20)


class RolePatchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    description: str | None = Field(default=None, max_length=200)
    status: str | None = Field(default=None, pattern=r"^(active|inactive)$")
    permissions: list[str] | None = Field(default=None, max_length=20)


class UserRoleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: UUID
    role_id: UUID


async def has_role(conn: AsyncConnection, user_id: str, role_name: str) -> bool:
    """Verifica si el usuario tiene asignado un rol activo específico."""
    res = await conn.execute(
        text(
            "SELECT EXISTS (SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id "
            "WHERE ur.user_id = CAST(:u AS uuid) AND r.name = :r AND r.status = 'active')"
        ),
        {"u": user_id, "r": role_name},
    )
    return bool(res.scalar())


async def remaining_active_admins(
    conn: AsyncConnection,
    *,
    excluding_user_id: str | None = None,
    excluding_assignment_id: str | None = None,
) -> int:
    """Cuenta cuántos administradores activos quedarían tras la operación (con lock)."""
    await conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": LAST_ADMIN_LOCK})
    if excluding_user_id is not None:
        q = text("""
            SELECT count(DISTINCT ur.user_id) 
            FROM user_roles ur 
            JOIN roles r ON r.id = ur.role_id 
            JOIN users u ON u.id = ur.user_id 
            WHERE r.name = 'ADMIN' 
              AND r.status = 'active' 
              AND u.status = 'active'
              AND ur.user_id <> CAST(:exc_uid AS uuid)
        """)
        res = await conn.execute(q, {"exc_uid": excluding_user_id})
    elif excluding_assignment_id is not None:
        q = text("""
            SELECT count(DISTINCT ur.user_id) 
            FROM user_roles ur 
            JOIN roles r ON r.id = ur.role_id 
            JOIN users u ON u.id = ur.user_id 
            WHERE r.name = 'ADMIN' 
              AND r.status = 'active' 
              AND u.status = 'active'
              AND ur.id <> CAST(:exc_urid AS uuid)
        """)
        res = await conn.execute(q, {"exc_urid": excluding_assignment_id})
    else:
        q = text("""
            SELECT count(DISTINCT ur.user_id) 
            FROM user_roles ur 
            JOIN roles r ON r.id = ur.role_id 
            JOIN users u ON u.id = ur.user_id 
            WHERE r.name = 'ADMIN' 
              AND r.status = 'active' 
              AND u.status = 'active'
        """)
        res = await conn.execute(q)
    return int(res.scalar() or 0)


async def load_role_by_id(conn: AsyncConnection, role_id: str) -> dict | None:
    """Carga los datos de un rol junto a sus permisos ordenados."""
    q = text("""
        SELECT 
            CAST(r.id AS text) AS id,
            r.name,
            r.description,
            r.status,
            r.builtin,
            r.created_at,
            r.updated_at,
            COALESCE(
                array_agg(rp.permission ORDER BY rp.permission) FILTER (WHERE rp.permission IS NOT NULL),
                ARRAY[]::text[]
            ) AS permissions
        FROM roles r
        LEFT JOIN role_permissions rp ON rp.role_id = r.id
        WHERE r.id = CAST(:id AS uuid)
        GROUP BY r.id
    """)
    row = (await conn.execute(q, {"id": role_id})).mappings().first()
    return dict(row) if row else None


async def load_role_permissions(conn: AsyncConnection, role_id: str) -> set[str]:
    """Obtiene los códigos de permisos asociados a un rol."""
    res = await conn.execute(
        text("SELECT permission FROM role_permissions WHERE role_id = CAST(:id AS uuid)"),
        {"id": role_id},
    )
    return set(res.scalars())


async def validate_catalog_permissions(conn: AsyncConnection, perms: list[str]) -> None:
    """Verifica que todos los códigos de permisos existan en la tabla permissions."""
    if not perms:
        return
    res = await conn.execute(
        text("SELECT count(*) FROM permissions WHERE code = ANY(CAST(:codes AS text[]))"),
        {"codes": list(set(perms))},
    )
    if (res.scalar() or 0) != len(set(perms)):
        raise HTTPException(422, "permiso desconocido")


def check_admin_privilege(
    is_caller_admin: bool,
    request: Request,
    who: UserIdentity,
    action_desc: str,
) -> None:
    """Aplica la regla R5 anti-escalada: rechaza y audita si no posee rol ADMIN."""
    if not is_caller_admin:
        audit.emit(
            "warning",
            "authz.denied",
            actor=f"user:{who.username}",
            target=request.url.path,
            ip=client_ip(request),
            details={"reason": "admin_role_required", "action": action_desc},
        )
        raise HTTPException(403, "solo un administrador puede realizar esta operación")


@router.post("/api/users", status_code=201)
async def create_user_endpoint(
    body: UserCreateIn,
    request: Request,
    who: UserIdentity = Depends(require_perm("users.manage")),
) -> dict:
    username = accounts.normalize(body.username)
    email = accounts.normalize_email(body.email)

    if not accounts.valid_credentials(username, body.password) or not accounts.valid_email(email):
        raise HTTPException(
            422,
            "usuario de 3–32 caracteres a-z, 0-9, '_', '.' o '-' y contraseña de ≥ 12 caracteres "
            "con 3 tipos, distinta del usuario, y correo electrónico válido",
        )

    user_id = str(uuid4())
    p_hash = await hash_secret_async(body.password)

    async with request.app.state.engine.begin() as conn:
        dup = (
            await conn.execute(
                text("SELECT 1 FROM users WHERE username = :u OR email = :e"),
                {"u": username, "e": email},
            )
        ).first()
        if dup:
            raise HTTPException(409, "usuario no disponible")

        await conn.execute(
            text(
                "INSERT INTO users (id, username, email, password_hash, status, created_by, updated_by) "
                "VALUES (CAST(:id AS uuid), :u, :e, :h, 'active', CAST(:who AS uuid), CAST(:who AS uuid))"
            ),
            {"id": user_id, "u": username, "e": email, "h": p_hash, "who": who.user_id},
        )
        row = (
            await conn.execute(
                text("SELECT created_at FROM users WHERE id = CAST(:id AS uuid)"),
                {"id": user_id},
            )
        ).first()

    audit.emit(
        "info",
        "user.created",
        actor=f"user:{who.username}",
        target=username,
        ip=client_ip(request),
        details={"user_id": user_id, "email": email},
    )
    return {
        "id": user_id,
        "username": username,
        "email": email,
        "status": "active",
        "created_at": row.created_at,
    }


@router.get("/api/users")
async def list_users_endpoint(
    request: Request,
    who: UserIdentity = Depends(require_perm("users.manage")),
) -> list[dict]:
    async with request.app.state.engine.connect() as conn:
        rows = (await conn.execute(USERS_LIST_QUERY)).mappings().all()
        return [dict(r) for r in rows]


@router.patch("/api/users/{user_id}")
async def patch_user_endpoint(
    user_id: UUID,
    body: UserPatchIn,
    request: Request,
    who: UserIdentity = Depends(require_perm("users.manage")),
) -> dict:
    if body.email is None and body.status is None:
        raise HTTPException(422, "debe proporcionar al menos un campo para actualizar")

    norm_email = accounts.normalize_email(body.email) if body.email else None
    if norm_email is not None and not accounts.valid_email(norm_email):
        raise HTTPException(422, "correo electrónico inválido")

    str_uid = str(user_id)
    if body.status == "inactive" and str_uid == str(who.user_id):
        raise HTTPException(409, "no puedes desactivar tu propia cuenta")

    async with request.app.state.engine.begin() as conn:
        user_row = (
            await conn.execute(
                text("SELECT id, username, email, status FROM users WHERE id = CAST(:id AS uuid)"),
                {"id": str_uid},
            )
        ).first()
        if user_row is None:
            raise HTTPException(404, "usuario no encontrado")

        if norm_email is not None:
            dup = (
                await conn.execute(
                    text("SELECT 1 FROM users WHERE email = :e AND id <> CAST(:id AS uuid)"),
                    {"e": norm_email, "id": str_uid},
                )
            ).first()
            if dup:
                raise HTTPException(409, "correo electrónico ya en uso")

        if body.status == "inactive":
            target_is_admin = await has_role(conn, str_uid, "ADMIN")
            if target_is_admin:
                rem = await remaining_active_admins(conn, excluding_user_id=str_uid)
                if rem == 0:
                    audit.emit(
                        "warning",
                        "admin.guard.last_admin",
                        actor=f"user:{who.username}",
                        target=user_row.username,
                        ip=client_ip(request),
                    )
                    raise HTTPException(409, "no se puede desactivar al último administrador")

            await conn.execute(
                text(
                    "UPDATE user_sessions SET ended_at = now(), end_reason = 'user_inactive' "
                    "WHERE user_id = CAST(:id AS uuid) AND ended_at IS NULL"
                ),
                {"id": str_uid},
            )

        updated_row = (
            (
                await conn.execute(
                    text(
                        "UPDATE users SET email = COALESCE(:e, email), status = COALESCE(:s, status), "
                        "updated_at = now(), updated_by = CAST(:who AS uuid) "
                        "WHERE id = CAST(:id AS uuid) "
                        "RETURNING CAST(id AS text) AS id, username, email, status, created_at, updated_at"
                    ),
                    {"e": norm_email, "s": body.status, "who": who.user_id, "id": str_uid},
                )
            )
            .mappings()
            .first()
        )

    audit.emit(
        "info",
        "user.updated",
        actor=f"user:{who.username}",
        target=user_row.username,
        ip=client_ip(request),
        details={"user_id": str_uid, "status": updated_row["status"]},
    )
    return dict(updated_row)


@router.get("/api/roles/permissions")
async def list_permissions_endpoint(
    request: Request,
    who: UserIdentity = Depends(require_perm("roles.manage")),
) -> list[dict]:
    async with request.app.state.engine.connect() as conn:
        res = await conn.execute(text("SELECT code, description FROM permissions ORDER BY code"))
        return [dict(r) for r in res.mappings()]


@router.post("/api/roles", status_code=201)
async def create_role_endpoint(
    body: RoleCreateIn,
    request: Request,
    who: UserIdentity = Depends(require_perm("roles.manage")),
) -> dict:
    perms = sorted(set(body.permissions))
    role_id = str(uuid4())

    async with request.app.state.engine.begin() as conn:
        await validate_catalog_permissions(conn, perms)
        caller_is_admin = await has_role(conn, who.user_id, "ADMIN")
        if any(p in ADMIN_PERMISSIONS for p in perms):
            check_admin_privilege(caller_is_admin, request, who, "create_admin_role")

        existing = (
            await conn.execute(
                text("SELECT 1 FROM roles WHERE name = :n"),
                {"n": body.name},
            )
        ).first()
        if existing:
            raise HTTPException(409, "ya existe un rol con ese nombre")

        await conn.execute(
            text(
                "INSERT INTO roles (id, name, description, status, builtin, created_by, updated_by) "
                "VALUES (CAST(:id AS uuid), :name, :desc, 'active', false, CAST(:who AS uuid), CAST(:who AS uuid))"
            ),
            {"id": role_id, "name": body.name, "desc": body.description, "who": who.user_id},
        )
        for p in perms:
            await conn.execute(
                text(
                    "INSERT INTO role_permissions (role_id, permission) "
                    "VALUES (CAST(:id AS uuid), :p)"
                ),
                {"id": role_id, "p": p},
            )
        created_role = await load_role_by_id(conn, role_id)

    audit.emit(
        "info",
        "role.created",
        actor=f"user:{who.username}",
        target=body.name,
        ip=client_ip(request),
        details={"role_id": role_id, "permissions": perms},
    )
    return created_role  # type: ignore[return-value]


@router.get("/api/roles")
async def list_roles_endpoint(
    request: Request,
    who: UserIdentity = Depends(require_perm("roles.manage")),
) -> list[dict]:
    async with request.app.state.engine.connect() as conn:
        rows = (await conn.execute(ROLES_LIST_QUERY)).mappings().all()
        return [dict(r) for r in rows]


@router.patch("/api/roles/{role_id}")
async def patch_role_endpoint(
    role_id: UUID,
    body: RolePatchIn,
    request: Request,
    who: UserIdentity = Depends(require_perm("roles.manage")),
) -> dict:
    if body.description is None and body.status is None and body.permissions is None:
        raise HTTPException(422, "debe proporcionar al menos un campo para actualizar")

    str_rid = str(role_id)
    perms = sorted(set(body.permissions)) if body.permissions is not None else None

    async with request.app.state.engine.begin() as conn:
        role_row = (
            await conn.execute(
                text(
                    "SELECT id, name, description, status, builtin FROM roles WHERE id = CAST(:id AS uuid)"
                ),
                {"id": str_rid},
            )
        ).first()
        if role_row is None:
            raise HTTPException(404, "rol no encontrado")
        if role_row.name == "ADMIN":
            raise HTTPException(409, "el rol ADMIN no se edita ni se desactiva")

        caller_is_admin = await has_role(conn, who.user_id, "ADMIN")
        existing_perms = await load_role_permissions(conn, str_rid)
        if any(p in ADMIN_PERMISSIONS for p in existing_perms):
            check_admin_privilege(caller_is_admin, request, who, "edit_role_with_admin_permissions")

        if perms is not None:
            await validate_catalog_permissions(conn, perms)
            if any(p in ADMIN_PERMISSIONS for p in perms):
                check_admin_privilege(caller_is_admin, request, who, "grant_admin_permissions")
            await conn.execute(
                text("DELETE FROM role_permissions WHERE role_id = CAST(:id AS uuid)"),
                {"id": str_rid},
            )
            for p in perms:
                await conn.execute(
                    text(
                        "INSERT INTO role_permissions (role_id, permission) "
                        "VALUES (CAST(:id AS uuid), :p)"
                    ),
                    {"id": str_rid, "p": p},
                )

        await conn.execute(
            text(
                "UPDATE roles SET description = COALESCE(:desc, description), "
                "status = COALESCE(:st, status), updated_at = now(), updated_by = CAST(:who AS uuid) "
                "WHERE id = CAST(:id AS uuid)"
            ),
            {"desc": body.description, "st": body.status, "who": who.user_id, "id": str_rid},
        )
        updated_role = await load_role_by_id(conn, str_rid)

    audit.emit(
        "info",
        "role.updated",
        actor=f"user:{who.username}",
        target=role_row.name,
        ip=client_ip(request),
        details={"role_id": str_rid},
    )
    return updated_role  # type: ignore[return-value]


@router.post("/api/user-roles", status_code=201)
async def assign_user_role_endpoint(
    body: UserRoleIn,
    request: Request,
    who: UserIdentity = Depends(require_perm("roles.manage")),
) -> dict:
    str_uid, str_rid = str(body.user_id), str(body.role_id)
    ur_id = str(uuid4())

    async with request.app.state.engine.begin() as conn:
        user_row = (
            await conn.execute(
                text("SELECT id, username, status FROM users WHERE id = CAST(:id AS uuid)"),
                {"id": str_uid},
            )
        ).first()
        if user_row is None:
            raise HTTPException(404, "usuario no encontrado")

        role_row = (
            await conn.execute(
                text("SELECT id, name, status FROM roles WHERE id = CAST(:id AS uuid)"),
                {"id": str_rid},
            )
        ).first()
        if role_row is None:
            raise HTTPException(404, "rol no encontrado")
        if role_row.status != "active":
            raise HTTPException(422, "el rol está inactivo")

        caller_is_admin = await has_role(conn, who.user_id, "ADMIN")
        if role_row.name == "ADMIN":
            check_admin_privilege(caller_is_admin, request, who, "assign_admin_role")

        existing = (
            await conn.execute(
                text(
                    "SELECT id FROM user_roles WHERE user_id = CAST(:uid AS uuid) AND role_id = CAST(:rid AS uuid)"
                ),
                {"uid": str_uid, "rid": str_rid},
            )
        ).first()
        if existing:
            raise HTTPException(409, "asignación existente")

        await conn.execute(
            text(
                "INSERT INTO user_roles (id, user_id, role_id, assigned_at, assigned_by) "
                "VALUES (CAST(:id AS uuid), CAST(:uid AS uuid), CAST(:rid AS uuid), now(), CAST(:who AS uuid))"
            ),
            {"id": ur_id, "uid": str_uid, "rid": str_rid, "who": who.user_id},
        )
        assigned_row = (
            await conn.execute(
                text("SELECT assigned_at FROM user_roles WHERE id = CAST(:id AS uuid)"),
                {"id": ur_id},
            )
        ).first()

    audit.emit(
        "info",
        "user_role.assigned",
        actor=f"user:{who.username}",
        target=f"user:{user_row.username}",
        ip=client_ip(request),
        details={"role": role_row.name, "assignment_id": ur_id},
    )
    return {
        "id": ur_id,
        "user_id": str_uid,
        "role_id": str_rid,
        "assigned_at": assigned_row.assigned_at,
    }


@router.delete("/api/user-roles/{assignment_id}", status_code=204)
async def revoke_user_role_endpoint(
    assignment_id: UUID,
    request: Request,
    who: UserIdentity = Depends(require_perm("roles.manage")),
) -> Response:
    str_urid = str(assignment_id)

    async with request.app.state.engine.begin() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT ur.id, ur.user_id, ur.role_id, u.username, r.name AS role_name "
                    "FROM user_roles ur "
                    "JOIN users u ON u.id = ur.user_id "
                    "JOIN roles r ON r.id = ur.role_id "
                    "WHERE ur.id = CAST(:id AS uuid)"
                ),
                {"id": str_urid},
            )
        ).first()
        if row is None:
            raise HTTPException(404, "asignación no encontrada")

        caller_is_admin = await has_role(conn, who.user_id, "ADMIN")
        if row.role_name == "ADMIN":
            check_admin_privilege(caller_is_admin, request, who, "revoke_admin_role")
            rem = await remaining_active_admins(conn, excluding_assignment_id=str_urid)
            if rem == 0:
                audit.emit(
                    "warning",
                    "admin.guard.last_admin",
                    actor=f"user:{who.username}",
                    target=row.username,
                    ip=client_ip(request),
                )
                raise HTTPException(409, "no se puede retirar el último administrador")

        await conn.execute(
            text("DELETE FROM user_roles WHERE id = CAST(:id AS uuid)"),
            {"id": str_urid},
        )

    audit.emit(
        "info",
        "user_role.revoked",
        actor=f"user:{who.username}",
        target=f"user:{row.username}",
        ip=client_ip(request),
        details={"role": row.role_name, "assignment_id": str_urid},
    )
    return Response(status_code=204)
