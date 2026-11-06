"""Servidor MCP de revisión de código: publica las herramientas de herramientas.py.

No se ejecuta a mano: lo lanza el cliente (la demo o revisor.py) como otro proceso y conversan por la
entrada y la salida estándar (transporte stdio) con mensajes JSON-RPC. stdout queda reservado para el
protocolo; lo que registra el servidor va a stderr y aparece en la consola con el prefijo [servidor].

Las herramientas de revisión son de solo lectura. Para la remediación hay tres más: guardar_correccion escribe
app.py en una COPIA de la aplicación (nunca el original), y ejecutar_pruebas y analizar_bandit_version miden
la versión original o la corregida.
"""
import json
import sys
import time
import warnings
from typing import Annotated

warnings.filterwarnings("ignore", module="pydantic_settings")

from mcp.server.fastmcp import FastMCP
from pydantic import Field

import herramientas as h

mcp = FastMCP("andina-revision-codigo", log_level="WARNING")


def _log(texto: str) -> None:
    print(f"[servidor] {texto}", file=sys.stderr, flush=True)


def _responder(nombre: str, t0: float, datos) -> str:
    texto = datos if isinstance(datos, str) else json.dumps(datos, ensure_ascii=False)
    _log(f"{nombre}: devuelvo {len(texto)} caracteres en {1000 * (time.perf_counter() - t0):.0f} ms")
    return texto


@mcp.tool()
def listar_archivos() -> str:
    """Lista los archivos de la aplicación que se está revisando."""
    t0 = time.perf_counter()
    _log("recibí tools/call listar_archivos()")
    return _responder("listar_archivos", t0, h.listar_archivos())


@mcp.tool()
def leer_codigo(
    archivo: Annotated[str, Field(description="Archivo dentro de la aplicación, por ejemplo app.py")] = "app.py",
    desde: Annotated[int, Field(description="Primera línea (1 = inicio)")] = 1,
    hasta: Annotated[int, Field(description="Última línea (0 = hasta el final)")] = 0,
) -> str:
    """Devuelve el código fuente con el número de cada línea."""
    t0 = time.perf_counter()
    _log(f"recibí tools/call leer_codigo(archivo={archivo!r}, desde={desde}, hasta={hasta})")
    try:
        return _responder("leer_codigo", t0, h.leer_codigo(archivo, desde, hasta))
    except ValueError as e:
        _log(f"leer_codigo: RECHAZADO ({e})")
        raise


@mcp.tool()
def analizar_bandit() -> str:
    """Ejecuta Bandit (reglas de seguridad para Python) sobre la aplicación y devuelve sus hallazgos con línea, regla, severidad y CWE."""
    t0 = time.perf_counter()
    _log("recibí tools/call analizar_bandit(): ejecuto bandit -r")
    return _responder("analizar_bandit", t0, h.bandit())


@mcp.tool()
def analizar_semgrep() -> str:
    """Ejecuta Semgrep con las reglas del equipo de Andina Pagos (incluye reglas de negocio) y devuelve sus hallazgos."""
    t0 = time.perf_counter()
    _log("recibí tools/call analizar_semgrep(): ejecuto semgrep con reglas_semgrep/andina.yml")
    r = h.semgrep()
    return _responder("analizar_semgrep", t0, r if r is not None else "Semgrep no está instalado en este equipo.")


@mcp.tool()
def auditar_dependencias() -> str:
    """Revisa requirements.txt con pip-audit contra las bases de vulnerabilidades de PyPI."""
    t0 = time.perf_counter()
    _log("recibí tools/call auditar_dependencias(): ejecuto pip-audit")
    filas, origen = h.pip_audit()
    _log(f"auditar_dependencias: origen de los datos = {origen}")
    return _responder("auditar_dependencias", t0, filas)


@mcp.tool()
def guardar_correccion(codigo: Annotated[str, Field(description="El archivo app.py COMPLETO, ya corregido")]) -> str:
    """Guarda app.py corregido en una copia de la aplicación (salidas/remediacion). Nunca modifica el original."""
    t0 = time.perf_counter()
    _log(f"recibí tools/call guardar_correccion(): {len(codigo.splitlines())} líneas")
    return _responder("guardar_correccion", t0, h.guardar_correccion(codigo))


@mcp.tool()
def ejecutar_pruebas(version: Annotated[str, Field(description="'original' o 'corregida'")] = "original") -> str:
    """Ejecuta las pruebas funcionales (la API no se rompe) y de seguridad (la falla está corregida) y devuelve el resultado de cada una."""
    t0 = time.perf_counter()
    _log(f"recibí tools/call ejecutar_pruebas({version!r}): ejecuto pytest")
    return _responder("ejecutar_pruebas", t0, h.pruebas_detalle(h.carpeta_version(version)))


@mcp.tool()
def analizar_bandit_version(version: Annotated[str, Field(description="'original' o 'corregida'")] = "original") -> str:
    """Ejecuta Bandit sobre la versión original o la corregida de la aplicación."""
    t0 = time.perf_counter()
    _log(f"recibí tools/call analizar_bandit_version({version!r})")
    return _responder("analizar_bandit_version", t0, h.bandit(h.carpeta_version(version)))


if __name__ == "__main__":
    _log(f"iniciado · aplicación revisada: {h.carpeta_app()} · espero mensajes JSON-RPC por stdin")
    mcp.run(transport="stdio")
