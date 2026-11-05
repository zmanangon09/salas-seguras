"""Formatos aceptados: firma, extensión y Content-Type (415) y decodificación previa (422)."""

import io
from collections.abc import Callable
from dataclasses import dataclass

from PIL import Image

from stego_svc import gif, jpeg, png, wav


@dataclass(frozen=True)
class Format:
    mime: str
    extensions: tuple[str, ...]
    content_types: tuple[str, ...]
    signature: bytes
    pillow: str | None  # formato que Pillow debe reconocer al decodificar; None si no es imagen
    technique: str
    analyze: Callable


FORMATS = {
    "image/png": Format(
        "image/png",
        (".png",),
        ("image/png",),
        b"\x89PNG\r\n\x1a\n",
        "PNG",
        "lsb_statistical_analysis",
        png.analyze,
    ),
    "image/jpeg": Format(
        "image/jpeg",
        (".jpg", ".jpeg"),
        ("image/jpeg",),
        b"\xff\xd8\xff",
        "JPEG",
        "structure_analysis",
        jpeg.analyze,
    ),
    "image/gif": Format(
        "image/gif", (".gif",), ("image/gif",), b"GIF8", "GIF", "structure_analysis", gif.analyze
    ),
    "audio/wav": Format(
        "audio/wav",
        (".wav",),
        ("audio/wav", "audio/x-wav", "audio/wave"),
        b"RIFF",
        None,
        "structure_analysis",
        wav.analyze,
    ),
}


def detect(data: bytes) -> str | None:
    """Formato según la firma (magic bytes); None si no está en FORMATS."""
    for mime, fmt in FORMATS.items():
        if data.startswith(fmt.signature):
            if mime == "audio/wav" and data[8:12] != b"WAVE":
                return None
            return mime
    return None


def matches(kind: str, filename: str, content_type: str | None) -> bool:
    """La extensión del nombre y el Content-Type de la parte coinciden con la firma."""
    fmt = FORMATS[kind]
    return filename.lower().endswith(fmt.extensions) and content_type in fmt.content_types


def decode_problems(kind: str, data: bytes, max_pixels: int) -> list[str]:
    """Lo que impide analizar el archivo (422): truncado, no decodificable o demasiado grande."""
    fmt = FORMATS[kind]
    if fmt.pillow is None:
        found = wav.structure(data)
        return [] if found["valid"] else ["RIFF/WAVE inválido o truncado"]
    try:
        with Image.open(io.BytesIO(data)) as image:
            if image.format != fmt.pillow:
                return ["el contenido no coincide con la firma"]
            if image.width * image.height > max_pixels:
                return ["demasiados píxeles"]
            image.load()  # decodifica todo: un archivo truncado falla aquí
    except Exception:  # Pillow lanza varios tipos según el daño; todos son 422
        return ["archivo truncado o no decodificable"]
    if kind == "image/gif" and not gif.structure(data)["valid"]:
        return ["GIF inválido o truncado"]
    return []


def validate(data: bytes, max_bytes: int = 5 * 1024 * 1024, max_pixels: int = 20_000_000):
    """(formato, motivos) para el laboratorio y las pruebas: formato None si no se puede analizar."""
    if len(data) > max_bytes:
        return None, ["archivo demasiado grande"]
    kind = detect(data)
    if kind is None:
        return None, ["firma o formato inválido"]
    problems = decode_problems(kind, data, max_pixels)
    return (None if problems else kind), problems
