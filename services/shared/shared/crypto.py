"""Utilidades criptográficas comunes (spec §11). Sin E/S: solo cálculos."""

import base64
import hashlib
import re
import secrets

# urlsafe_b64decode descarta en silencio lo que no es del alfabeto ("QU!!JD" → b"ABC").
_B64URL = re.compile(r"[A-Za-z0-9_-]*")


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64d(text: str) -> bytes:
    """Lanza ValueError si el texto no es base64url."""
    if not _B64URL.fullmatch(text):
        raise ValueError("no es base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def token_hash(token: str) -> bytes:
    """Los tokens tienen ≥ 128 bits de entropía: un hash rápido basta para guardarlos (spec §11.1)."""
    return sha256(token.encode())
