"""Utilidades de los ataques: copiar la aplicación, modificarla y correr el revisor con y sin controles."""
import json
import shutil
import subprocess
import sys
from pathlib import Path

LAB = Path(__file__).resolve().parent.parent
SALIDAS = LAB / "salidas"


def copiar_app(nombre: str) -> Path:
    destino = SALIDAS / "ataques" / nombre / "app_andina"
    if destino.exists():
        shutil.rmtree(destino)
    shutil.copytree(LAB / "app_andina", destino, ignore=shutil.ignore_patterns("__pycache__"))
    return destino


def insertar_despues(archivo: Path, ancla: str, texto: str) -> int:
    """Inserta texto en la línea siguiente a la que contiene ancla. Devuelve el número de la línea insertada."""
    lineas = archivo.read_text(encoding="utf-8").splitlines()
    i = next(k for k, l in enumerate(lineas) if ancla in l)
    lineas.insert(i + 1, texto)
    archivo.write_text("\n".join(lineas) + "\n", encoding="utf-8")
    return i + 2


def correr(app: Path, controles: str, etiqueta: str, extra: list[str]) -> dict:
    cmd = [sys.executable, str(LAB / "revisor.py"), "--app", str(app), "--controles", controles, "--etiqueta", etiqueta,
           "--detalle", "0", "--sin-parche", *extra]
    print(f"\n=== revisor con --controles {controles} ===", flush=True)
    r = subprocess.run(cmd, cwd=LAB)
    if r.returncode != 0:
        raise SystemExit("El revisor terminó con error: revisen el mensaje de arriba.")
    return json.loads((SALIDAS / f"{etiqueta}.json").read_text(encoding="utf-8"))


def tabla(filas: list[tuple[str, str, str]]):
    print("\n" + "─" * 96)
    print(f"  {'Indicador':<52} {'Sin controles':<20} {'Con controles':<20}")
    print("─" * 96)
    for k, a, b in filas:
        print(f"  {k:<52} {a:<20} {b:<20}")
    print("─" * 96)
