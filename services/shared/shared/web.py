"""Base común de los servicios (spec §4.3, §15): token de servicio, errores JSON genéricos y /health."""

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text
from starlette.exceptions import HTTPException as StarletteHTTPException

from shared.observability import RequestContextMiddleware, configure_logging
from shared.service_auth import ServiceTokenMiddleware

SESSION_COOKIE = "__Host-session"  # el JWT (spec §8.1)


def set_cookie(response: Response, name: str, value: str, max_age: int | None = None) -> None:
    response.set_cookie(
        name, value, max_age=max_age, path="/", secure=True, httponly=True, samesite="strict"
    )


def clear_cookie(response: Response, name: str) -> None:
    response.delete_cookie(name, path="/", secure=True, httponly=True, samesite="strict")


def create_base_app(*, title: str, settings, engine, service_auth, lifespan=None) -> FastAPI:
    configure_logging(title)
    app = FastAPI(title=title, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.settings = settings
    app.state.engine = engine
    app.state.service_auth = service_auth
    app.add_middleware(ServiceTokenMiddleware)
    app.add_middleware(RequestContextMiddleware)  # el último agregado es el más externo

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        detail = exc.detail if isinstance(exc.detail, str) else "error"
        return JSONResponse({"error": detail}, status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse({"error": "datos inválidos"}, status_code=422)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        # el detalle ya lo registró RequestContextMiddleware, con el request_id
        return JSONResponse({"error": "error interno"}, status_code=500)

    @app.get("/health")
    async def health() -> JSONResponse:
        if engine is None:  # servicio sin BD (stego)
            return JSONResponse({"status": "ok"})
        try:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
        except Exception:  # la BD no responde: el healthcheck de Docker lo verá
            return JSONResponse({"error": "bd no disponible"}, status_code=503)
        return JSONResponse({"status": "ok"})

    return app
