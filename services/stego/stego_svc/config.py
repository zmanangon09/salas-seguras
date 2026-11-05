"""Configuración de stego (spec §19, §23.7)."""

from dataclasses import dataclass

from shared.secrets import db_url, env, origins


@dataclass(frozen=True)
class Settings:
    database_url: str
    quarantine_dir: str = "/data"  # volumen stego_quarantine: solo stego lo monta
    allowed_origins: frozenset[str] = frozenset({"https://localhost"})
    upload_max_bytes: int = 5 * 1024 * 1024
    max_image_pixels: int = 20_000_000
    analyze_per_min: int = 10
    stego_chi2_p: float = 0.995
    stego_rs_rate: float = 0.15
    stego_entropy_trigger: float | None = None
    stego_timeout_s: float = 10.0

    def __post_init__(self) -> None:
        # Fallar cerrado: un umbral NaN o fuera de (0, 1] apagaría el detector sin aviso.
        for name in ("stego_chi2_p", "stego_rs_rate", "stego_entropy_trigger"):
            value = getattr(self, name)
            if value is not None and not 0 < value <= 1:  # NaN también falla
                raise ValueError(f"{name} fuera de (0, 1]")

    @property
    def thresholds(self) -> dict:
        return {
            "chi2_p": self.stego_chi2_p,
            "rs_rate": self.stego_rs_rate,
            "entropy_trigger": self.stego_entropy_trigger,
            "max_pixels": self.max_image_pixels,
        }


def load_settings() -> Settings:
    return Settings(
        database_url=db_url("stego", "app"),
        quarantine_dir=env("STEGO_QUARANTINE_DIR", "/data"),
        allowed_origins=origins(),
        upload_max_bytes=env("UPLOAD_MAX_BYTES", 5 * 1024 * 1024),
        max_image_pixels=env("MAX_IMAGE_PIXELS", 20_000_000),
        analyze_per_min=env("ANALYZE_PER_MIN", 10),
        stego_chi2_p=env("STEGO_CHI2_P", 0.995),
        stego_rs_rate=env("STEGO_RS_RATE", 0.15),
        stego_entropy_trigger=env("STEGO_ENTROPY_TRIGGER", None),
        stego_timeout_s=env("STEGO_TIMEOUT_S", 10.0),
    )
