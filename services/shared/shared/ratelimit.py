"""Límites de intentos fallidos (spec §9.1) y token bucket del análisis de imágenes (spec §9.9)."""

import time
from collections.abc import Callable

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection


async def failures(conn: AsyncConnection, key: str, window_min: int) -> int:
    result = await conn.execute(
        text(
            "SELECT count(*) FROM failed_attempts "
            "WHERE key = :key AND created_at > now() - make_interval(mins => :window)"
        ),
        {"key": key, "window": window_min},
    )
    return result.scalar_one()


async def any_over(conn: AsyncConnection, limits: list[tuple[str, int]], window_min: int) -> bool:
    """True si alguna clave alcanzó su máximo de fallos dentro de la ventana."""
    for key, limit in limits:
        if await failures(conn, key, window_min) >= limit:
            return True
    return False


async def record(conn: AsyncConnection, keys: list[str], window_min: int) -> int:
    """Registra un fallo por clave y devuelve el mayor conteo resultante (para el retraso progresivo)."""
    for key in keys:
        await conn.execute(text("INSERT INTO failed_attempts (key) VALUES (:key)"), {"key": key})
    return max([await failures(conn, key, window_min) for key in keys], default=0)


class TokenBucket:
    """Token bucket en memoria; stego guarda una instancia por usuario."""

    def __init__(self, rate: float, burst: int, clock: Callable[[], float] = time.monotonic):
        self.rate, self.burst, self.clock = rate, burst, clock
        self.tokens, self.updated = float(burst), clock()

    def allow(self) -> bool:
        now = self.clock()
        self.tokens = min(self.burst, self.tokens + (now - self.updated) * self.rate)
        self.updated = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False
