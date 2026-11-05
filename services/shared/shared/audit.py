"""Eventos de seguridad como registros JSON (spec §14).

En el primer parcial no hay servicio audit: cada servicio escribe sus eventos en su salida estándar
(una línea JSON por evento con LOG_FORMAT=json) y se leen con `docker compose logs`.
"""

import logging

log = logging.getLogger("audit")
log.setLevel(logging.INFO)  # los eventos de seguridad no dependen del nivel por defecto (WARNING)

LEVELS = {"info": logging.INFO, "warning": logging.WARNING, "critical": logging.CRITICAL}


def emit(
    severity: str,
    action: str,
    *,
    actor: str,
    target: str | None = None,
    ip: str | None = None,
    details: dict | None = None,
) -> None:
    log.log(
        LEVELS[severity],
        action,
        extra={"event": {"actor": actor, "target": target, "ip": ip, "details": details or {}}},
    )
