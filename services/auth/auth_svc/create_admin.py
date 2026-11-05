"""Crea el admin global (spec §9.1, §23.4). No hay credenciales por defecto.

Uso dentro del contenedor: python -m auth_svc.create_admin <usuario> --email <correo> [--password-stdin]
"""

import argparse
import asyncio
import sys
from getpass import getpass

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine

from auth_svc.accounts import create_admin, normalize
from auth_svc.config import load_settings
from shared.observability import configure_logging


def read_password(from_stdin: bool) -> str:
    """Lee la contraseña desde stdin o la solicita interactivamente dos veces."""
    if from_stdin:
        return sys.stdin.readline().rstrip("\n")
    password = getpass("Contraseña: ")
    if password != getpass("Repite la contraseña: "):
        sys.exit("las contraseñas no coinciden")
    return password


async def run(username: str, password: str, email: str | None = None) -> None:
    engine = create_async_engine(load_settings().database_url)
    try:
        await create_admin(engine, username, password, email=email)
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Crea el admin global")
    parser.add_argument("username", help="nombre de usuario del administrador")
    parser.add_argument("--email", default=None, help="correo electrónico del administrador")
    parser.add_argument(
        "--password-stdin", action="store_true", help="lee la contraseña desde entrada estándar"
    )
    args = parser.parse_args()

    configure_logging("auth")
    password = read_password(args.password_stdin)
    try:
        asyncio.run(run(args.username, password, email=args.email))
    except ValueError as exc:
        sys.exit(str(exc))
    except IntegrityError:
        sys.exit("ese usuario o correo ya existe")

    print(f"admin {normalize(args.username)} creado")


if __name__ == "__main__":
    main()
