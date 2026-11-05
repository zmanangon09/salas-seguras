"""Veredicto y política del enunciado (§2.3) y de la spec §23.7."""

ACTIONS = {
    "sin_indicios": "ninguna",
    "sospechoso": "cuarentena",
    "no_concluyente": "advertencia",
    "error": "rechazo",
}

LIMITATIONS = {
    "lsb_statistical_analysis": (
        "Resultado indicativo, no prueba de esteganografía. LSB matching (±1) y el embebido "
        "adaptativo pueden evadir chi² y RS."
    ),
    "structure_analysis": (
        "Solo se revisa la estructura del archivo (datos tras el final, metadatos y bloques "
        "desconocidos); no se analizan los píxeles ni las muestras."
    ),
    "file_validation": "El archivo no se analizó: no pasó la validación previa.",
}


def classify(result: dict) -> str:
    """Una anomalía es un indicio (sospechoso). Sin estadísticos calculables, nunca sin_indicios."""
    if result.get("failed"):  # tiempo excedido o fallo del analizador
        return "no_concluyente"
    if result.get("reasons"):
        return "sospechoso"
    if result.get("inconclusive"):
        return "no_concluyente"
    return "sin_indicios"
