"""Servicio auth (spec §9.1)."""

from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from auth_svc import admin, internal, routes
from auth_svc.config import Settings, load_settings
from auth_svc.tokens import Signer
from shared.service_auth import ServiceAuth
from shared.web import create_base_app


def create_app(
    settings: Settings | None = None,
    *,
    engine: AsyncEngine | None = None,
    service_auth: ServiceAuth | None = None,
) -> FastAPI:
    settings = settings or load_settings()
    app = create_base_app(
        title="auth",
        settings=settings,
        engine=engine or create_async_engine(settings.database_url, pool_pre_ping=True),
        service_auth=service_auth or ServiceAuth.from_secrets("auth"),
    )
    app.state.signer = Signer(settings.jwt_private_key, settings.jwt_issuer, settings.jwt_audience)
    for module in (routes, internal, admin):
        app.include_router(module.router)
    return app
