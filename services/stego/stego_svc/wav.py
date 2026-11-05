"""Análisis estructural acotado de RIFF/WAVE."""

from stego_svc.png import chunk_name


def structure(data):
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        return {"valid": False, "chunks": [], "data_bytes": 0, "trailing_bytes": 0}
    declared = int.from_bytes(data[4:8], "little") + 8
    position, chunks, data_bytes = 12, [], 0
    while position + 8 <= len(data) and position < declared:
        kind = data[position : position + 4]
        size = int.from_bytes(data[position + 4 : position + 8], "little")
        end = position + 8 + size
        if end > len(data):
            return {"valid": False, "chunks": chunks, "data_bytes": data_bytes, "trailing_bytes": 0}
        chunks.append(chunk_name(kind))
        data_bytes += size if kind == b"data" else 0
        position = end + (size & 1)
    return {
        "valid": "fmt " in chunks and "data" in chunks,
        "chunks": chunks,
        "data_bytes": data_bytes,
        "trailing_bytes": max(0, len(data) - declared),
    }


def structural_reasons(found):
    reasons = []
    if not found.get("valid"):
        reasons.append("RIFF/WAVE inválido o truncado")
    if found.get("data_bytes", 0) > 50 * 1024 * 1024:
        reasons.append("audio demasiado grande")
    if found.get("trailing_bytes", 0) > 0:
        reasons.append("datos después del RIFF")
    return reasons


def analyze(data, cfg):
    found = structure(data)
    reasons = structural_reasons(found)
    return {"suspicious": bool(reasons), "reasons": reasons, "metrics": found}
