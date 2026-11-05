"""Configuración de auth (spec §19, §23)."""

from dataclasses import dataclass

from shared.secrets import db_url, env, origins, read_secret


@dataclass(frozen=True)
class Settings:
    database_url: str
    jwt_private_key: str  # PEM PKCS#8 (RSA); solo auth la tiene (spec §4.3)
    allowed_origins: frozenset[str] = frozenset({"https://localhost"})
    jwt_issuer: str = "auth"
    jwt_audience: str = "secure-chat"
    jwt_ttl_min: int = 15
    session_idle_min: int = 30
    session_abs_hours: int = 8
    login_max_fails: int = 5
    login_window_min: int = 15
    login_delay_base: float = 0.25
    register_max_per_hour: int = 10


def load_settings() -> Settings:
    return Settings(
        database_url=db_url("auth", "app"),
        jwt_private_key=read_secret("jwt_signing_key"),
        allowed_origins=origins(),
        jwt_issuer=env("JWT_ISSUER", "auth"),
        jwt_audience=env("JWT_AUDIENCE", "secure-chat"),
        jwt_ttl_min=env("JWT_TTL_MIN", 15),
        session_idle_min=env("SESSION_IDLE_MIN", 30),
        session_abs_hours=env("SESSION_ABS_HOURS", 8),
        login_max_fails=env("LOGIN_MAX_FAILS", 5),
        login_window_min=env("LOGIN_WINDOW_MIN", 15),
        login_delay_base=env("LOGIN_DELAY_BASE", 0.25),
        register_max_per_hour=env("REGISTER_MAX_PER_HOUR", 10),
    )
