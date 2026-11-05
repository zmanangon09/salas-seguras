"""Genera los secretos de deploy/secrets/ y el certificado TLS de deploy/certs/.

Nunca sobrescribe un secreto existente; --rotate NOMBRE regenera uno (y lo que se deriva de él).
Uso:  docker compose -f deploy/docker-compose.yml run --rm setup [--rotate NOMBRE]
      (o, con `cryptography` instalado: python deploy/gen_secrets.py [--rotate NOMBRE] [--dir RUTA])
"""

import argparse
import hashlib
import os
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SERVICES = ("auth", "stego")  # los que tienen BD
CALLERS = ("gateway",)  # quienes llaman a los servicios; en el primer parcial, solo el gateway
RANDOM = (
    "postgres_password",
    *(f"db_{svc}_{role}" for svc in SERVICES for role in ("owner", "app")),
    *(f"svc_token_{caller}" for caller in CALLERS),
)
# Las contraseñas de BD no se rotan aquí: Postgres solo las lee al crear el volumen; cambiarlas
# requiere ALTER ROLE ... PASSWORD en la BD y luego el archivo.
ROTATABLE = (*(f"svc_token_{caller}" for caller in CALLERS), "jwt_signing_key")
TLS_DAYS = 825  # el máximo que macOS e iOS aceptan para un certificado TLS


def new_jwt_key() -> str:
    """RSA de 3072 bits para los JWT RS256 de auth."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _usage(**granted: bool) -> x509.KeyUsage:
    flags = ("digital_signature", "content_commitment", "key_encipherment", "data_encipherment")
    flags += ("key_agreement", "key_cert_sign", "crl_sign", "encipher_only", "decipher_only")
    return x509.KeyUsage(**{flag: granted.get(flag, False) for flag in flags})


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def new_tls_cert() -> tuple[str, str, str]:
    """ECDSA P-256 para localhost, firmado por una CA local. Devuelve (CA, certificado, clave).

    La clave de la CA nunca se escribe: nadie puede firmar otro certificado con esa CA, así que
    agregarla a Postman (o al sistema) solo hace confiar en este certificado.
    """
    start = datetime.now(UTC) - timedelta(minutes=5)  # tolera un reloj algo atrasado
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Salas Seguras CA local")])

    def base(subject: x509.Name, public_key: ec.EllipticCurvePublicKey) -> x509.CertificateBuilder:
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_name)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(start)
            .not_valid_after(start + timedelta(days=TLS_DAYS))  # el tope se mide desde el inicio
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        )

    ca = (
        base(ca_name, ca_key.public_key())
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_usage(key_cert_sign=True, crl_sign=True), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    ips = (ip_address("127.0.0.1"), ip_address("::1"))
    names = [x509.DNSName("localhost"), *(x509.IPAddress(ip) for ip in ips)]
    cert = (
        base(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]), key.public_key())
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_usage(digital_signature=True), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return _pem(ca), _pem(cert), key_pem


class Generator:
    def __init__(self, root: Path, rotate: str | None) -> None:
        self.secrets_dir = root / "secrets"
        self.certs_dir = root / "certs"
        self.rotate = rotate

    def path(self, name: str) -> Path:
        return self.secrets_dir / name

    def read(self, name: str) -> str:
        return self.path(name).read_text(encoding="utf-8").strip()

    def write(self, path: Path, content: str, mode: int = 0o644) -> None:
        """Atómica (temporal + os.replace) y con LF: los archivos se montan en contenedores Linux.

        0o644: legible por el uid 10001 del contenedor; el directorio de secretos es 0700.
        """
        tmp = path.with_name(f".{path.name}.tmp")
        tmp.unlink(missing_ok=True)  # el que haya dejado una corrida cortada
        # Nace privado y en exclusiva (con O_EXCL tampoco sigue un symlink): nadie alcanza a leer
        # una clave a medio escribir ni a desviarla a otro archivo.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as file:
            file.write(content)
        tmp.chmod(mode)
        os.replace(tmp, path)
        print(f"generado: {path.parent.name}/{path.name}")

    def ensure(self, name: str, make: Callable[[], str]) -> None:
        if self.rotate == name or not self.path(name).exists():
            self.write(self.path(name), make())

    def derive(self, name: str, content: str) -> None:
        """Lo derivado de un token se recalcula siempre: queda al día aunque un --rotate se corte."""
        path = self.path(name)
        if not path.exists() or path.read_text(encoding="utf-8") != content:
            self.write(path, content)

    def ensure_tls(self) -> None:
        """Certificado del gateway. Uno que ya exista (por ejemplo, de mkcert) se respeta."""
        if (self.certs_dir / "fullchain.pem").exists():
            return
        self.certs_dir.mkdir(exist_ok=True)
        ca, cert, key = new_tls_cert()
        self.write(self.certs_dir / "privkey.pem", key, 0o600)  # la lee el master de nginx (root)
        self.write(self.certs_dir / "ca.pem", ca)  # la que se agrega a Postman
        self.write(self.certs_dir / "fullchain.pem", cert)  # al final: si algo se corta, se rehace

    def run(self) -> None:
        self.secrets_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.secrets_dir.chmod(0o700)  # mkdir no corrige un directorio que ya existía
        for name in RANDOM:
            self.ensure(name, lambda: secrets.token_urlsafe(32))
        for caller in CALLERS:
            token = self.read(f"svc_token_{caller}")
            self.derive(f"svc_hash_{caller}", hashlib.sha256(token.encode()).hexdigest())
        token = self.read("svc_token_gateway")
        self.derive("gateway_token.conf", f'proxy_set_header X-Service-Token "{token}";\n')
        self.ensure("jwt_signing_key", new_jwt_key)
        self.ensure_tls()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rotate", choices=ROTATABLE, help="secreto a regenerar")
    parser.add_argument("--dir", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    Generator(args.dir, args.rotate).run()


if __name__ == "__main__":
    main()
