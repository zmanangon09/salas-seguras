"""JWT RS256 que apunta a una sesión del servidor (spec §8.1; riesgo 16).

El algoritmo va fijo al verificar: un token con `alg: none`, o uno firmado con HS256 usando la
clave pública como secreto, no pasa. La revocación no depende del `exp`: la decide la sesión (verify).
"""

import time
from datetime import datetime

import jwt
from cryptography.hazmat.primitives import serialization

REQUIRED_CLAIMS = ["iss", "aud", "sub", "sid", "iat", "exp"]


class Signer:
    def __init__(self, private_pem: str, issuer: str, audience: str) -> None:
        self._private = serialization.load_pem_private_key(private_pem.encode(), password=None)
        self._public = self._private.public_key()
        self.issuer, self.audience = issuer, audience

    def issue(
        self,
        *,
        user_id: str,
        username: str,
        session_id: str,
        roles: list[str],
        expires_at: datetime,
    ) -> str:
        claims = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": user_id,
            "sid": session_id,
            "name": username,
            "roles": roles,  # solo informativo: la autorización usa los permisos de la BD
            "iat": int(time.time()),
            "exp": int(expires_at.timestamp()),
        }
        return jwt.encode(claims, self._private, algorithm="RS256")

    def read(self, token: str) -> dict | None:
        """Claims de un JWT con firma, emisor, audiencia y vencimiento válidos; None en otro caso."""
        try:
            return jwt.decode(
                token,
                self._public,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": REQUIRED_CLAIMS},
            )
        except jwt.PyJWTError:
            return None
