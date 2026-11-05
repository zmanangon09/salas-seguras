"""Servicio stego (spec §23.7)."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from shared.service_auth import ServiceAuth
from shared.web import create_base_app
from stego_svc import pipeline, routes
from stego_svc.config import Settings, load_settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = pipeline.new_pool()
    try:
        yield
    finally:
        app.state.pool.shutdown(wait=False, cancel_futures=True)


def create_app(
    settings: Settings | None = None,
    *,
    engine: AsyncEngine | None = None,
    service_auth: ServiceAuth | None = None,
) -> FastAPI:
    settings = settings or load_settings()
    app = create_base_app(
        title="stego",
        settings=settings,
        engine=engine or create_async_engine(settings.database_url, pool_pre_ping=True),
        service_auth=service_auth or ServiceAuth.from_secrets("stego"),
        lifespan=lifespan,
    )
    app.state.buckets = {}  # token bucket por usuario (R10)
    app.include_router(routes.router)
    return app
