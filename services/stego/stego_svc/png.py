"""Validación estructural y análisis de píxeles PNG."""

import io

import numpy as np
from PIL import Image

from stego_svc import stego

KNOWN = {
    b"IHDR",
    b"PLTE",
    b"IDAT",
    b"IEND",
    b"tRNS",
    b"cHRM",
    b"gAMA",
    b"iCCP",
    b"sRGB",
    b"pHYs",
    b"eXIf",
    b"tIME",
    b"tEXt",
    b"zTXt",
    b"iTXt",
}
TEXT = {b"tEXt", b"zTXt", b"iTXt"}


def decoded(image):
    if image.mode in ("I", "F") or image.mode.startswith("I;16"):
        values = np.asarray(image).astype(float)
        top = 65535.0 if values.max() > 255 else 255.0
        image = Image.fromarray(np.clip(values * 255 / top, 0, 255).astype(np.uint8))
    alpha = image.mode in ("RGBA", "LA", "PA") or "transparency" in image.info
    return image.convert("RGBA" if alpha else "RGB")


def chunk_name(kind: bytes) -> str:
    """ID de chunk legible; si trae bytes no imprimibles (un NUL rompe el jsonb), va en hexadecimal."""
    return kind.decode("ascii") if all(0x20 <= b < 0x7F for b in kind) else kind.hex()


def structure(data):
    position, text_bytes, unknown, trailing = 8, 0, [], 0
    while position + 12 <= len(data):
        length = int.from_bytes(data[position : position + 4], "big")
        kind = data[position + 4 : position + 8]
        end = position + length + 12
        if end > len(data):
            break
        if kind in TEXT:
            text_bytes += length
        elif kind not in KNOWN:
            unknown.append(chunk_name(kind))
        position = end
        if kind == b"IEND":
            trailing = max(0, len(data) - end)
            break
    return {"trailing_bytes": trailing, "text_bytes": text_bytes, "unknown_chunks": unknown}


def structural_reasons(found):
    reasons = []
    if found["trailing_bytes"]:
        reasons.append("datos después de IEND")
    if found["text_bytes"] > 1024:
        reasons.append("chunks de texto grandes")
    if found["unknown_chunks"]:
        reasons.append("chunks desconocidos")
    return reasons


MIN_PIXELS = 1000  # por debajo, chi² y RS no son fiables (spec §23.7)


def analyze(data, cfg):
    found = structure(data)
    with Image.open(io.BytesIO(data), formats=["PNG"]) as image:
        pixels = np.asarray(decoded(image).convert("RGB"))
    if pixels.shape[0] * pixels.shape[1] < MIN_PIXELS:
        empty = {
            "chi2_p": None,
            "rs_rate": None,
            "lsb_entropy_mean": None,
            "lsb_entropy_high_fraction": None,
        }
        reasons = structural_reasons(found)
        return {
            "suspicious": bool(reasons),
            "inconclusive": True,
            "reasons": reasons,
            "metrics": {**found, **empty},
        }
    chi = stego.chi2_scan(pixels)
    rs = max(stego.rs_estimate(pixels[..., c]) for c in range(3))
    entropy, high = stego.lsb_entropy(pixels)
    reasons = structural_reasons(found)
    if chi >= cfg.get("chi2_p", 0.95):
        reasons.append("chi² del plano LSB")
    if rs >= cfg.get("rs_rate", 0.08):
        reasons.append("análisis RS")
    trigger = cfg.get("entropy_trigger")
    if trigger is not None and high >= trigger:
        reasons.append("entropía del plano LSB")
    return {
        "suspicious": bool(reasons),
        "reasons": reasons,
        "metrics": {
            **found,
            "chi2_p": stego.finite(chi),
            "rs_rate": stego.finite(rs),
            "lsb_entropy_mean": stego.finite(entropy),
            "lsb_entropy_high_fraction": stego.finite(high),
        },
    }
