"""Laboratorio de estegoanálisis: embebe LSB, genera las imágenes de la demo y calibra umbrales.

Uso (desde la raíz):
  python services/stego/tools/stego_lab.py demo postman/imagenes
  python services/stego/tools/stego_lab.py embed entrada.png salida.png --rate 0.1 --mode seq
  python services/stego/tools/stego_lab.py calibrate services/stego/tools/calibracion
"""

import argparse
import io
import sys
import zipfile
from pathlib import Path

import numpy as np
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # stego_svc sin instalar

from stego_svc import png  # noqa: E402
from stego_svc.synthetic import embed_lsb, natural_image, png_bytes  # noqa: E402
from stego_svc.verdict import classify  # noqa: E402

CFG = {"chi2_p": 0.995, "rs_rate": 0.15, "entropy_trigger": None}
RATES = (0.05, 0.10, 0.25, 0.50)


def embed(args) -> None:
    pixels = np.asarray(Image.open(args.input).convert("RGB"))
    Path(args.output).write_bytes(png_bytes(embed_lsb(pixels, args.rate, args.mode)))


def demo(args) -> None:
    """T09 y T10: la referencia, la misma con LSB, una con un ZIP al final y las de rechazo."""
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    clean = natural_image(0, 256)  # semilla 0: ningún detector se dispara
    reference = png_bytes(clean)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zipped:
        entry = zipfile.ZipInfo("mensaje.txt", date_time=(2026, 11, 4, 0, 0, 0))  # reproducible
        zipped.writestr(entry, "datos ocultos al final del PNG")
    rng = np.random.default_rng(7)
    noise = rng.integers(0, 256, (1400, 1400, 3), dtype=np.uint8)  # ~5,9 MB: no se comprime
    files = {
        "referencia.png": reference,
        "lsb.png": png_bytes(embed_lsb(clean, 0.5, "random")),
        "zip-al-final.png": reference + archive.getvalue(),
        "no-es-imagen.png": b"MZ\x90\x00" + b"\x00" * 60 + b"ejecutable renombrado a .png",
        "truncada.png": reference[: len(reference) // 2],
        "grande.png": png_bytes(noise),  # T10 (413); no se versiona
    }
    for name, data in files.items():
        (out / name).write_bytes(data)
    print(f"imágenes de demo escritas en {out}")


def calibrate(args) -> None:
    paths = sorted(
        p for p in Path(args.folder).iterdir() if p.suffix.lower() in (".png", ".jpg", ".jpeg")
    )
    if len(paths) < 15:
        raise SystemExit("se requieren al menos 15 imágenes")
    variants = {"limpia": []} | {f"{m} {r:.0%}": [] for m in ("seq", "random") for r in RATES}
    for path in paths:
        image = Image.open(path).convert("RGB")
        image.thumbnail((1024, 1024), Image.Resampling.LANCZOS)
        clean = np.asarray(image).copy()
        variants["limpia"].append(png.analyze(png_bytes(clean), CFG))
        for mode in ("seq", "random"):
            for rate in RATES:
                altered = png_bytes(embed_lsb(clean, rate, mode))
                variants[f"{mode} {rate:.0%}"].append(png.analyze(altered, CFG))
    print("variante | sin_indicios | sospechoso | no_concluyente | total")
    for name, results in variants.items():
        verdicts = [classify(item) for item in results]
        counts = [verdicts.count(v) for v in ("sin_indicios", "sospechoso", "no_concluyente")]
        print(f"{name} | {' | '.join(map(str, counts))} | {len(results)}")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("embed")
    p.add_argument("input")
    p.add_argument("output")
    p.add_argument("--rate", type=float, default=0.1)
    p.add_argument("--mode", choices=("seq", "random"), default="seq")
    sub.add_parser("demo").add_argument("output")
    sub.add_parser("calibrate").add_argument("folder")
    args = parser.parse_args()
    {"embed": embed, "demo": demo, "calibrate": calibrate}[args.command](args)


if __name__ == "__main__":
    main()
