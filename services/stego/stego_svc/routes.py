"""API de stego (spec §23.7): análisis con registro y consulta de resultados con propiedad."""

import hashlib
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from shared import audit
from shared.identity import UserIdentity, client_ip, require_perm
from shared.ratelimit import TokenBucket
from stego_svc import formats, pipeline
from stego_svc.verdict import ACTIONS, LIMITATIONS, classify

router = APIRouter()

READ_ANY = "steganography.results.read_any"
UNAVAILABLE = (SQLAlchemyError, OSError)  # BD caída o volumen de cuarentena inaccesible → 503


def _emit(request: Request, who: UserIdentity, severity: str, event: str, **details) -> None:
    audit.emit(
        severity,
        event,
        actor=f"user:{who.username}",
        target=request.url.path,
        ip=client_ip(request),
        details=details,
    )


def _check_rate(request: Request, who: UserIdentity) -> None:
    per_min = request.app.state.settings.analyze_per_min
    buckets = request.app.state.buckets
    bucket = buckets.setdefault(who.user_id, TokenBucket(rate=per_min / 60, burst=per_min))
    if not bucket.allow():
        _emit(request, who, "warning", "stego.ratelimited")
        raise HTTPException(429, "límite de análisis excedido")


async def _persist(request: Request, record: dict, data: bytes) -> None:
    """Sospechoso: primero el archivo en cuarentena y después el INSERT; si algo falla → 503."""
    settings, engine = request.app.state.settings, request.app.state.engine
    path = None
    try:
        if record["action"] == "cuarentena":
            path = pipeline.quarantine(settings.quarantine_dir, record["id"], data)
        await pipeline.save(engine, record)
    except UNAVAILABLE:
        if path is not None:
            path.unlink(missing_ok=True)
        details = {k: record[k] for k in ("sha256", "status")}
        audit.emit(
            "critical",
            "stego.persist_failed",
            actor="service:stego",
            details={"analysis_id": record["id"], **details},
        )
        raise HTTPException(503, "servicio no disponible") from None


async def _reject(request, who, record, data, code: int, error: str) -> JSONResponse:
    record.update(technique="file_validation", status="error", action="rechazo", indicators={})
    await _persist(request, record, data)
    _emit(request, who, "warning", "stego.rejected", analysis_id=record["id"], code=code)
    return JSONResponse({"error": error, "analysis_id": record["id"]}, status_code=code)


@router.post("/api/steganography/analyze")
async def analyze(
    request: Request,
    file: UploadFile = File(...),
    who: UserIdentity = Depends(require_perm("steganography.analyze")),
):
    settings = request.app.state.settings
    _check_rate(request, who)
    data = await file.read(settings.upload_max_bytes + 1)
    if len(data) > settings.upload_max_bytes:
        _emit(request, who, "warning", "stego.rejected", code=413, size_bytes=len(data))
        raise HTTPException(413, "archivo demasiado grande")
    name = pipeline.clean_name(file.filename)
    kind = formats.detect(data)
    record = {
        "id": str(uuid4()),
        "user_id": who.user_id,
        "filename": name,
        "mime": None,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "reasons": [],
    }
    if kind is None or not formats.matches(kind, name, file.content_type):
        record["reasons"] = ["firma, extensión o Content-Type no admitidos"]
        return await _reject(request, who, record, data, 415, "formato no admitido")
    record["mime"] = kind
    cfg = settings.thresholds
    result = await pipeline.analyze_isolated(
        request.app.state, kind, data, cfg, settings.stego_timeout_s
    )
    if result.get("problems"):
        record["reasons"] = result["problems"]
        return await _reject(request, who, record, data, 422, "archivo no permitido")
    status = classify(result)
    record.update(
        technique=formats.FORMATS[kind].technique,
        status=status,
        action=ACTIONS[status],
        indicators=pipeline.indicators(kind, result["metrics"], cfg),
        reasons=result["reasons"],
    )
    await _persist(request, record, data)
    severity = "info" if status == "sin_indicios" else "warning"
    _emit(
        request,
        who,
        severity,
        "stego.analyzed",
        analysis_id=record["id"],
        sha256=record["sha256"],
        status=status,
        action=record["action"],
    )
    return await _read(request, record["id"])


async def _read(request: Request, analysis_id: str) -> dict | None:
    try:
        found = await pipeline.fetch(request.app.state.engine, analysis_id)
    except UNAVAILABLE:
        raise HTTPException(503, "servicio no disponible") from None
    if found is not None:
        found["limitations"] = LIMITATIONS[found["technique"]]
    return found


@router.get("/api/steganography/results/{analysis_id}")
async def result(
    analysis_id: str,
    request: Request,
    who: UserIdentity = Depends(require_perm("steganography.results.read")),
):
    try:
        analysis_id = str(UUID(analysis_id))  # forma canónica: Postgres no acepta urn:uuid:
    except ValueError:
        raise HTTPException(404, "no encontrado") from None
    found = await _read(request, analysis_id)
    if found is None:
        raise HTTPException(404, "no encontrado")
    # La propiedad sale de la identidad del gateway, nunca de un parámetro (T11).
    if found["user_id"] != who.user_id and READ_ANY not in who.perms:
        _emit(request, who, "warning", "perm.denied", required=[READ_ANY])
        raise HTTPException(403, "permiso insuficiente")
    _emit(request, who, "info", "stego.result.read", analysis_id=analysis_id)
    return found
