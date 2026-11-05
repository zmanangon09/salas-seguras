"""Pasos del análisis que no dependen de HTTP (spec §23.7): nombre, análisis aislado y registro."""

import asyncio
import json
import multiprocessing
import os
import unicodedata
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from pathlib import Path, PureWindowsPath

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from shared import audit
from stego_svc import formats

MAX_NAME = 255
# ponytail: 2 procesos de análisis; un análisis que se cuelga ocupa uno hasta terminar.
# Si el tiempo excedido se vuelve frecuente, reciclar el pool al cortar por tiempo.
WORKERS = 2

INSERT = text(
    "INSERT INTO analyses (id, user_id, filename, mime, size_bytes, sha256, technique, status, "
    "action, indicators, reasons) VALUES (CAST(:id AS uuid), CAST(:user_id AS uuid), :filename, "
    ":mime, :size_bytes, :sha256, :technique, :status, :action, CAST(:indicators AS jsonb), "
    "CAST(:reasons AS jsonb))"
)
SELECT = text(
    "SELECT id::text AS analysis_id, user_id::text AS user_id, filename, mime, sha256, technique, "
    "status, indicators, reasons, action, created_at FROM analyses WHERE id = CAST(:id AS uuid)"
)


def clean_name(name: str | None) -> str:
    """Basename en NFC y sin caracteres de control. Solo informativo: nunca se usa como ruta."""
    base = PureWindowsPath(name or "").name  # corta tanto en / como en \
    base = unicodedata.normalize("NFC", base)
    return "".join(ch for ch in base if unicodedata.category(ch)[0] != "C")


def new_pool() -> ProcessPoolExecutor:
    # forkserver: el hijo no hereda los hilos del proceso principal (fork con hilos puede colgarse).
    methods = multiprocessing.get_all_start_methods()
    context = multiprocessing.get_context("forkserver" if "forkserver" in methods else "spawn")
    return ProcessPoolExecutor(max_workers=WORKERS, mp_context=context)


def run_analysis(kind: str, data: bytes, cfg: dict) -> dict:
    """Corre en un proceso del pool: decodificar y analizar. Si revienta, no tumba el servicio."""
    problems = formats.decode_problems(kind, data, cfg["max_pixels"])
    if problems:
        return {"problems": problems}
    return formats.FORMATS[kind].analyze(data, cfg)


async def analyze_isolated(state, kind: str, data: bytes, cfg: dict, timeout: float) -> dict:
    """Si el análisis falla o se pasa de tiempo, el resultado es no_concluyente (fallar cerrado)."""
    loop = asyncio.get_running_loop()
    pool = state.pool
    try:
        future = loop.run_in_executor(pool, run_analysis, kind, data, cfg)
        return await asyncio.wait_for(future, timeout)
    except TimeoutError:
        reason = "el análisis excedió el tiempo límite"
    except BrokenProcessPool:
        # Un worker murió (memoria, fallo de una librería en C): sin esto, todo saldría no_concluyente.
        if state.pool is pool:  # otra petición pudo haberlo recreado ya
            state.pool = new_pool()
            pool.shutdown(wait=False, cancel_futures=True)
            audit.emit("warning", "stego.pool_restarted", actor="service:stego")
        reason = "el análisis falló"
    # ponytail: el analizador lanza; el detalle no sale al cliente
    except Exception:
        reason = "el análisis falló"
    return {"failed": True, "reasons": [reason], "metrics": {}}


def indicators(kind: str | None, metrics: dict, cfg: dict) -> dict:
    if kind != "image/png":
        return metrics
    return {
        **metrics,
        "chi2_p_threshold": cfg["chi2_p"],
        "rs_rate_threshold": cfg["rs_rate"],
    }


def quarantine(directory: str, analysis_id: str, data: bytes) -> Path:
    """Escribe el archivo sospechoso con permisos 0600; el nombre es el UUID, nunca el del cliente."""
    path = Path(directory) / analysis_id
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        with os.fdopen(os.open(path, flags, 0o600), "wb") as handle:
            handle.write(data)
    except BaseException:
        path.unlink(missing_ok=True)  # sin archivos a medias (disco lleno)
        raise
    return path


async def save(engine: AsyncEngine, record: dict) -> None:
    values = {
        **record,
        "filename": record["filename"][:MAX_NAME],
        "indicators": json.dumps(record["indicators"]),
        "reasons": json.dumps(record["reasons"]),
    }
    async with engine.begin() as conn:
        await conn.execute(INSERT, values)


async def fetch(engine: AsyncEngine, analysis_id: str) -> dict | None:
    async with engine.connect() as conn:
        row = (await conn.execute(SELECT, {"id": analysis_id})).mappings().first()
    if row is None:
        return None
    found = dict(row)
    for key in ("indicators", "reasons"):
        if isinstance(found[key], str):
            found[key] = json.loads(found[key])
    found["sha256"] = found["sha256"].strip()
    found["created_at"] = found["created_at"].isoformat()
    return found
