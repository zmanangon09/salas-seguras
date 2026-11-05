"""Estadísticos LSB de estegoanálisis."""

import math

import numpy as np
from scipy.stats import chi2

MASK = np.array([0, 1, 1, 0], dtype=bool)


def finite(value):
    value = float(value)
    return value if math.isfinite(value) else None


def chi2_pvalue(values):
    hist = np.bincount(np.asarray(values).ravel(), minlength=256).astype(float)
    even, odd = hist[0::2], hist[1::2]
    expected = (even + odd) / 2
    valid = expected > 4
    dof = int(valid.sum()) - 1
    if dof < 1:
        return 0.0
    statistic = float((((even - expected) ** 2)[valid] / expected[valid]).sum())
    return float(chi2.sf(statistic, dof))


def chi2_scan(pixels, min_pixels=1000):
    flat = pixels.reshape(-1, pixels.shape[-1]) if pixels.ndim == 3 else pixels.reshape(-1, 1)
    best = 0.0
    for fraction in (0.1, 0.25, 0.5, 1.0):
        count = int(len(flat) * fraction)
        if count < min_pixels and fraction < 1.0:
            continue
        for channel in range(flat.shape[1]):
            best = max(best, chi2_pvalue(flat[:count, channel]))
    return best


def _groups(channel):
    h, w = channel.shape[0] // 2 * 2, channel.shape[1] // 2 * 2
    blocks = channel[:h, :w].astype(np.int16).reshape(h // 2, 2, w // 2, 2).transpose(0, 2, 1, 3)
    return blocks.reshape(-1, 4)[:, [0, 1, 3, 2]]


def _variation(groups):
    return np.abs(np.diff(groups, axis=1)).sum(axis=1)


def _rs_counts(groups):
    base = _variation(groups)
    positive, negative = groups.copy(), groups.copy()
    positive[:, MASK] ^= 1
    negative[:, MASK] = ((negative[:, MASK] + 1) ^ 1) - 1
    fp, fn = _variation(positive), _variation(negative)
    return (fp > base).mean(), (fp < base).mean(), (fn > base).mean(), (fn < base).mean()


def rs_estimate(channel):
    groups = _groups(channel)
    if len(groups) == 0:
        return 0.0
    rm, sm, rnm, snm = _rs_counts(groups)
    r1, s1, rn1, sn1 = _rs_counts(groups ^ 1)
    d0, d1, dn0, dn1 = rm - sm, r1 - s1, rnm - snm, rn1 - sn1
    a, b, c = 2 * (d1 + d0), dn0 - dn1 - d1 - 3 * d0, d0 - dn0
    if abs(a) < 1e-12:
        x = -c / b if abs(b) >= 1e-12 else 0.0
    else:
        discriminant = b * b - 4 * a * c
        if discriminant < 0:
            return 0.0
        roots = ((-b + math.sqrt(discriminant)) / (2 * a), (-b - math.sqrt(discriminant)) / (2 * a))
        x = min(roots, key=abs)
    return float(min(max(x / (x - 0.5), 0.0), 1.0)) if abs(x - 0.5) >= 1e-12 else 0.0


def lsb_entropy(pixels, block=64):
    planes = pixels[..., None] if pixels.ndim == 2 else pixels
    h, w = planes.shape[:2]
    bh, bw = min(block, h), min(block, w)
    nh, nw = max(1, h // bh), max(1, w // bw)
    bits = (planes[: nh * bh, : nw * bw] & 1).astype(float)
    p = bits.reshape(nh, bh, nw, bw, -1).mean(axis=(1, 3))
    with np.errstate(divide="ignore", invalid="ignore"):
        entropy = -(
            np.where(p > 0, p * np.log2(p), 0) + np.where(p < 1, (1 - p) * np.log2(1 - p), 0)
        )
    return float(entropy.mean()), float((entropy >= 0.999).mean())
