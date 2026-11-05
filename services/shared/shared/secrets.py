"""Lectura de Docker secrets (/run/secrets) y de perillas no secretas (spec §11, §19).

Si falta un secreto, el servicio no arranca: fallar cerrado.
"""

import os
from pathlib import Path
from urllib.parse import quote


def secrets_dir() -> Path:
    return Path(os.environ.get("SECRETS_DIR", "/run/secrets"))


def read_secret(name: str) -> str:
    try:
        value = (secrets_dir() / name).read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        raise RuntimeError(f"secreto requerido ausente: {name}") from None
    if not value:
        raise RuntimeError(f"secreto vacío: {name}")
    return value


def env(name: str, default):
    """Perilla no secreta del entorno, convertida al tipo del valor por defecto.

    Un default None indica una perilla float opcional que se desactiva con "" u "off".
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    if default is None:
        return None if raw in ("", "off") else float(raw)
    return type(default)(raw)


def origins() -> frozenset[str]:
    raw = env("ALLOWED_ORIGINS", "https://localhost")
    return frozenset(origin.strip() for origin in raw.split(",") if origin.strip())


def db_url(service: str, role: str) -> str:
    """URL asyncpg del rol <service>_<role>; su contraseña sale del secreto db_<service>_<role>."""
    password = quote(read_secret(f"db_{service}_{role}"), safe="")
    host, port = env("DB_HOST", "db"), env("DB_PORT", 5432)
    return f"postgresql+asyncpg://{service}_{role}:{password}@{host}:{port}/{service}"
