"""Opcional · Compara todas las corridas del revisor que hay en salidas/ (modelos y combinaciones de controles).

Uso:  python comparar.py
Resultado: salidas/comparacion.xlsx y la tabla en pantalla.
"""
import json

import pandas as pd

from llm import BASE

SALIDAS = BASE / "salidas"
COLUMNAS = ["Proveedor", "Controles", "Fallas de la referencia encontradas", "Hallazgos sin respaldo en la referencia",
            "Hallazgos descartados por C2", "Hallazgos agregados por C2 (omitidos por la IA)", "Parche", "Vueltas del modelo", "Segundos"]

filas = []
for archivo in sorted(SALIDAS.glob("revision_*.json")):
    r = json.loads(archivo.read_text(encoding="utf-8"))["resumen"]
    filas.append({"Corrida": archivo.stem, **{c: r.get(c, "") for c in COLUMNAS}})
if not filas:
    raise SystemExit("No hay corridas en salidas/. Ejecuten antes revisor.py.")
df = pd.DataFrame(filas)
df.to_excel(SALIDAS / "comparacion.xlsx", index=False)
with pd.option_context("display.max_columns", None, "display.width", 200, "display.max_colwidth", 28):
    print(df.drop(columns=["Corrida"]).to_string(index=False))
print("\nDetalle: salidas/comparacion.xlsx. Si corrieron el mismo modelo varias veces, ¿los resultados se mantienen?")
