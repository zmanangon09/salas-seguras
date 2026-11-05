"""Generadores deterministas para pruebas y demostraciones."""

import io

import numpy as np
from PIL import Image


def natural_image(seed=0, size=256):
    rng = np.random.default_rng(seed)
    y, x = np.mgrid[0:size, 0:size].astype(float)
    base = 110 + 60 * np.sin(x / 23) * np.cos(y / 31) + 30 * np.sin((x + y) / 47)
    rgb = np.stack([base, base * 0.8 + 20, 255 - base * 0.9], axis=-1) + rng.normal(
        0, 2, (size, size, 3)
    )
    buf = io.BytesIO()
    Image.fromarray(np.clip(rgb, 0, 255).astype(np.uint8)).save(buf, format="JPEG", quality=85)
    return np.asarray(Image.open(io.BytesIO(buf.getvalue())).convert("RGB")).copy()


def embed_lsb(pixels, rate, mode="seq", seed=1):
    flat = pixels.reshape(-1).copy()
    count = int(len(flat) * rate)
    rng = np.random.default_rng(seed)
    bits = rng.integers(0, 2, count, dtype=np.uint8)
    index = np.arange(count) if mode == "seq" else rng.choice(len(flat), count, replace=False)
    flat[index] = (flat[index] & 0xFE) | bits
    return flat.reshape(pixels.shape)


def png_bytes(pixels, **kwargs):
    buf = io.BytesIO()
    Image.fromarray(pixels).save(buf, format="PNG", **kwargs)
    return buf.getvalue()


def jpeg_bytes(pixels, quality=90, **kwargs):
    buf = io.BytesIO()
    Image.fromarray(pixels).save(buf, format="JPEG", quality=quality, **kwargs)
    return buf.getvalue()
