"""Validación estructural JPEG."""


def skip_entropy(data, position):
    while True:
        position = data.find(b"\xff", position)
        if position < 0 or position + 1 >= len(data):
            return len(data)
        following = data[position + 1]
        if following == 0 or 0xD0 <= following <= 0xD7:
            position += 2
            continue
        return position


def structure(data):
    position, metadata, end = 2, 0, None
    while position + 1 < len(data):
        if data[position] != 0xFF:
            break
        marker = data[position + 1]
        if marker == 0xFF:
            position += 1
            continue
        if marker == 0xD9:
            end = position + 2
            break
        if 0xD0 <= marker <= 0xD7 or marker == 1:
            position += 2
            continue
        if position + 4 > len(data):
            break
        length = int.from_bytes(data[position + 2 : position + 4], "big")
        if 0xE0 <= marker <= 0xEF or marker == 0xFE:
            metadata += length
        position += 2 + length
        if marker == 0xDA:
            position = skip_entropy(data, position)
    return {"trailing_bytes": len(data) - end if end is not None else 0, "metadata_bytes": metadata}


def structural_reasons(found):
    reasons = []
    if found["trailing_bytes"] > 16:
        reasons.append("datos después de EOI")
    if found["metadata_bytes"] > 65536:
        reasons.append("metadatos excesivos")
    return reasons


def analyze(data, cfg):
    found = structure(data)
    reasons = structural_reasons(found)
    return {"suspicious": bool(reasons), "reasons": reasons, "metrics": found}
