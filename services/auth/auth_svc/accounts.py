"""Cuentas: normalización, política y consultas (spec §8.1, §23.3, §23.4)."""

import re
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from shared import audit
from shared.passwords import hash_secret_async, strong_enough

USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+$")

BY_USERNAME = text(
    "SELECT id::text AS id, username, email, password_hash, status FROM users WHERE username = :u"
)
BY_ID = text(
    "SELECT id::text AS id, username, email, status FROM users WHERE id = CAST(:id AS uuid)"
)
ACTIVE_ROLES = text(
    "SELECT r.name FROM user_roles ur "
    "JOIN roles r ON r.id = ur.role_id "
    "WHERE ur.user_id = CAST(:user AS uuid) AND r.status = 'active' "
    "ORDER BY r.name"
)
ACTIVE_PERMISSIONS = text(
    "SELECT DISTINCT rp.permission FROM user_roles ur "
    "JOIN roles r ON r.id = ur.role_id "
    "JOIN role_permissions rp ON rp.role_id = r.id "
    "WHERE ur.user_id = CAST(:user AS uuid) AND r.status = 'active' "
    "ORDER BY rp.permission"
)


def normalize(username: str) -> str:
    """Normaliza el nombre de usuario (espacios afuera y minúsculas)."""
    return username.strip().lower()


def normalize_email(email: str) -> str:
    """Normaliza la dirección de correo electrónico (espacios afuera y minúsculas)."""
    return email.strip().lower()


def valid_credentials(username: str, password: str) -> bool:
    """Usuario a-z0-9_.- de 3–32; contraseña ≥ 12, 3 de 4 clases y distinta del usuario (spec §8.1)."""
    return bool(USERNAME_RE.fullmatch(username)) and strong_enough(password, forbid=username)


def valid_email(email: str) -> bool:
    """Valida formato básico de email y longitud máxima RFC 5321 (254 chars)."""
    return len(email) <= 254 and bool(EMAIL_RE.fullmatch(email))


async def insert_user(
    conn: AsyncConnection,
    username: str,
    email: str,
    password_hash: str,
    *,
    status: str = "active",
) -> str:
    """Crea una cuenta en la tabla users. Lanza IntegrityError si username o email ya existen."""
    user_id = str(uuid4())
    await conn.execute(
        text(
            "INSERT INTO users (id, username, email, password_hash, status) "
            "VALUES (CAST(:id AS uuid), :u, :email, :hash, :status)"
        ),
        {"id": user_id, "u": username, "email": email, "hash": password_hash, "status": status},
    )
    return user_id


async def by_username(conn: AsyncConnection, username: str):
    """Obtiene la fila del usuario por su nombre normalizado."""
    return (await conn.execute(BY_USERNAME, {"u": username})).first()


async def by_id(conn: AsyncConnection, user_id: str):
    """Obtiene la fila del usuario por su ID."""
    return (await conn.execute(BY_ID, {"id": user_id})).first()


async def active_role_names(conn: AsyncConnection, user_id: str) -> list[str]:
    """Lista de nombres de roles activos asignados al usuario."""
    return list((await conn.execute(ACTIVE_ROLES, {"user": user_id})).scalars())


async def active_permissions(conn: AsyncConnection, user_id: str) -> set[str]:
    """Conjunto de códigos de permisos vigentes a través de roles activos."""
    return set((await conn.execute(ACTIVE_PERMISSIONS, {"user": user_id})).scalars())


async def create_admin(
    engine: AsyncEngine,
    username: str,
    password: str,
    email: str | None = None,
) -> str:
    """Admin global (spec §9.1, §23.4): creado solo por CLI. Devuelve su ID."""
    username = normalize(username)
    email = normalize_email(email) if email else f"{username}@localhost"

    if not valid_credentials(username, password):
        raise ValueError(
            "usuario de 3–32 caracteres a-z, 0-9, '_', '.' o '-' y contraseña de ≥ 12 caracteres "
            "con 3 tipos (minúsculas, mayúsculas, dígitos, símbolos), distinta del usuario"
        )
    if not valid_email(email):
        raise ValueError("correo electrónico inválido (debe cumplir formato RFC 5321)")

    password_hash = await hash_secret_async(password)
    async with engine.begin() as conn:
        user_id = await insert_user(conn, username, email, password_hash, status="active")
        await conn.execute(
            text(
                "INSERT INTO user_roles (id, user_id, role_id) "
                "SELECT CAST(:ur_id AS uuid), CAST(:user_id AS uuid), id "
                "FROM roles WHERE name = 'ADMIN'"
            ),
            {"ur_id": str(uuid4()), "user_id": user_id},
        )
    audit.emit("info", "admin.create", actor="system", target=username)
    return user_id
