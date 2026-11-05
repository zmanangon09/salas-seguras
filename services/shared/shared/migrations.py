"""Punto de entrada común de Alembic: cada servicio migra solo su BD, con su rol owner (spec §7.6)."""

import asyncio

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

from shared.secrets import db_url


def _migrate(connection) -> None:
    context.configure(connection=connection, target_metadata=None)
    with context.begin_transaction():
        context.run_migrations()


def run(service: str) -> None:
    """La URL sale del secreto db_<svc>_owner: sin él, no migra (fallar cerrado).

    Solo quien corre Alembic en su mismo proceso (las pruebas) puede pasarla en
    config.attributes["url"]; nunca por el entorno.
    """
    url = context.config.attributes.get("url") or db_url(service, "owner")

    async def main() -> None:
        engine = create_async_engine(url)
        try:
            async with engine.connect() as connection:
                await connection.run_sync(_migrate)
        finally:
            await engine.dispose()

    asyncio.run(main())
