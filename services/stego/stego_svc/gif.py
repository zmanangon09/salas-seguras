"""Análisis estructural acotado de GIF."""

import io

from PIL import Image


def _color_table(packed: int) -> int:
    """Bytes de la tabla de color que sigue a un descriptor con el bit 0x80."""
    return 3 * (2 ** ((packed & 7) + 1)) if packed & 0x80 else 0


def _sub_blocks(data: bytes, position: int) -> tuple[int, int]:
    """Salta una cadena de sub-bloques; devuelve (posición siguiente, bytes de datos)."""
    total = 0
    while position < len(data):
        size = data[position]
        position += 1
        if size == 0:
            break
        total += size
        position += size
    return position, total


def _image(data: bytes, position: int) -> int | None:
    """Descriptor de imagen, tabla local, tamaño LZW mínimo y datos; None si está truncado."""
    if position + 9 > len(data):
        return None
    position += 9 + _color_table(data[position + 8])
    if position >= len(data):
        return None
    return _sub_blocks(data, position + 1)[0]


def structure(data):
    invalid = {"valid": False, "frames": 0, "trailing_bytes": 0, "comments_bytes": 0}
    if not data.startswith((b"GIF87a", b"GIF89a")) or len(data) < 13:
        return invalid
    width = int.from_bytes(data[6:8], "little")
    height = int.from_bytes(data[8:10], "little")
    position = 13 + _color_table(data[10])
    frames, comments, end = 0, 0, None
    while position < len(data) and end is None:
        marker, position = data[position], position + 1
        if marker == 0x3B:
            end = position
        elif marker == 0x2C:
            position = _image(data, position)
            if position is None:
                return {**invalid, "frames": frames, "comments_bytes": comments}
            frames += 1
        elif marker == 0x21 and position < len(data):
            label = data[position]
            position, total = _sub_blocks(data, position + 1)
            comments += total if label == 0xFE else 0
        else:
            return {**invalid, "frames": frames, "comments_bytes": comments}
    return {
        "valid": frames > 0 and end is not None,
        "frames": frames,
        "width": width,
        "height": height,
        "trailing_bytes": len(data) - end if end is not None else 0,
        "comments_bytes": comments,
    }


def structural_reasons(found):
    reasons = []
    if not found.get("valid"):
        reasons.append("GIF inválido o truncado")
    if found.get("frames", 0) > 100:
        reasons.append("demasiados frames")
    if found.get("comments_bytes", 0) > 1024:
        reasons.append("comentarios excesivos")
    if found.get("trailing_bytes", 0):
        reasons.append("datos después del trailer GIF")
    return reasons


def analyze(data, cfg):
    found = structure(data)
    reasons = structural_reasons(found)
    try:
        with Image.open(io.BytesIO(data)) as image:
            if image.width * image.height > cfg.get("max_pixels", 20_000_000):
                reasons.append("demasiados píxeles")
    except Exception:
        if "GIF inválido o truncado" not in reasons:
            reasons.append("GIF inválido o truncado")
    return {"suspicious": bool(reasons), "reasons": reasons, "metrics": found}
