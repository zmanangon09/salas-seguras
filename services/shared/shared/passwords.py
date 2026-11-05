"""Argon2id para las contraseñas de las cuentas (riesgo 4, spec §11.1).

Perfil RFC 9106 de baja memoria (t=3, m=64 MiB, p=4), el predeterminado de argon2-cffi.
"""

import threading

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from starlette.concurrency import run_in_threadpool

_hasher = PasswordHasher()
# ponytail: tope global de 4 cálculos simultáneos (4 × 64 MiB) para que un ataque de logins
# masivos no agote la RAM; súbelo si el host tiene memoria de sobra.
_SLOTS = threading.BoundedSemaphore(4)
_DUMMY_HASH = _hasher.hash("dummy-password-timing-only")


def hash_secret(secret: str) -> str:
    with _SLOTS:
        return _hasher.hash(secret)


def verify_secret(stored_hash: str | None, secret: str) -> bool:
    """Sin hash (usuario inexistente) verifica contra un dummy: mismo tiempo, siempre False."""
    with _SLOTS:
        try:
            matched = _hasher.verify(stored_hash or _DUMMY_HASH, secret)
        except (VerificationError, InvalidHashError):
            return False
    return matched and stored_hash is not None


async def hash_secret_async(secret: str) -> str:
    return await run_in_threadpool(hash_secret, secret)


async def verify_secret_async(stored_hash: str | None, secret: str) -> bool:
    return await run_in_threadpool(verify_secret, stored_hash, secret)


def strong_enough(secret: str, *, forbid: str = "") -> bool:
    """≥ 12 caracteres, ≥ 3 de 4 clases (minúsculas, mayúsculas, dígitos, símbolos) y distinta de `forbid`."""
    classes = sum(
        (
            any(c.islower() for c in secret),
            any(c.isupper() for c in secret),
            any(c.isdigit() for c in secret),
            any(not c.isalnum() for c in secret),
        )
    )
    return len(secret) >= 12 and classes >= 3 and secret.casefold() != forbid.casefold()
