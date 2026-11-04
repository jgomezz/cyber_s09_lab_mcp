"""Kit MCP del curso: registro de lo que pasa por debajo y conexión de un cliente a un servidor MCP.

Lo usan la demo, el laboratorio y los ataques. Cada evento queda numerado en pantalla y en un archivo JSONL:
  MCP →  mensaje JSON-RPC del cliente al servidor        MCP ←  respuesta del servidor
  LLM →  lo que se envía al modelo                       LLM ←  lo que responde el modelo
  CTRL   lo que hace un control (C1, C2…)                INFO   notas del programa
y [servidor] es lo que el propio servidor escribe en su registro (stderr).
"""
import json
import os
import sys
import time
import warnings
from contextlib import asynccontextmanager

warnings.filterwarnings("ignore", module="pydantic_settings")  # aviso interno del SDK, sin efecto

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import Implementation


class Registro:
    """Imprime cada evento numerado y lo guarda en JSONL. detalle: 0 = nada, 1 = una línea, 2 = JSON completo."""
    COLOR = {"MCP →": "36", "MCP ←": "96", "LLM →": "33", "LLM ←": "93", "CTRL": "95", "INFO": "90", "ALERTA": "91"}

    def __init__(self, archivo, detalle: int = 1):
        self.n, self.t0, self.detalle, self.eventos = 0, time.perf_counter(), detalle, []
        self.color = sys.stdout.isatty() and not os.getenv("NO_COLOR")
        if self.color and os.name == "nt":
            os.system("")  # activa los colores ANSI en la consola de Windows
        archivo.parent.mkdir(parents=True, exist_ok=True)
        self.f = archivo.open("w", encoding="utf-8")

    def __call__(self, canal: str, texto: str, cuerpo=None):
        self.n += 1
        t = time.perf_counter() - self.t0
        ev = {"n": self.n, "t": round(t, 3), "canal": canal, "evento": texto, "cuerpo": cuerpo}
        self.eventos.append(ev)
        self.f.write(json.dumps(ev, ensure_ascii=False, default=str) + "\n")
        self.f.flush()
        if self.detalle == 0 and canal not in ("CTRL", "ALERTA"):
            return
        linea = f"[{self.n:02d}] {t:6.2f}s  {canal:<6} {texto}"
        print(f"\033[{self.COLOR.get(canal, '0')}m{linea}\033[0m" if self.color else linea, flush=True)
        if self.detalle >= 2 and cuerpo is not None:
            s = json.dumps(cuerpo, ensure_ascii=False, indent=2, default=str)
            if len(s) > 2500:
                s = s[:2500] + "\n… (recortado en pantalla; completo en el registro)"
            print("        " + s.replace("\n", "\n        "))

    def cerrar(self):
        self.f.close()


def una_linea(m: dict) -> str:
    """Describe en una línea un mensaje JSON-RPC."""
    if "method" in m:
        tipo = "notificación" if "id" not in m else f"petición id={m['id']}"
        extra = ""
        if m["method"] == "tools/call":
            p = m.get("params", {})
            extra = f"  {p.get('name')}({json.dumps(p.get('arguments', {}), ensure_ascii=False)[:120]})"
        return f"{m['method']} ({tipo}){extra}"
    if "error" in m:
        return f"error id={m.get('id')}: {m['error'].get('message')}"
    r = m.get("result", {})
    if "serverInfo" in r:
        return f"respuesta id={m.get('id')}: servidor '{r['serverInfo'].get('name')}', protocolo {r.get('protocolVersion')}"
    if "tools" in r:
        return f"respuesta id={m.get('id')}: {len(r['tools'])} herramienta(s): " + ", ".join(t["name"] for t in r["tools"])
    if "content" in r:
        texto = "".join(c.get("text", "") for c in r["content"])
        error = " · isError" if r.get("isError") else ""
        try:
            datos = json.loads(texto)
            if isinstance(datos, list):
                return f"respuesta id={m.get('id')}: lista de {len(datos)} elemento(s){error}"
        except (json.JSONDecodeError, TypeError):
            pass
        return f"respuesta id={m.get('id')}: {len(texto)} caracteres{error}"
    return f"respuesta id={m.get('id')}"


def intercalar_registro(read, write, reg: Registro):
    """Pone dos canales entre la sesión MCP y el transporte para registrar cada mensaje que pasa."""
    entrada_tx, entrada_rx = anyio.create_memory_object_stream(64)
    salida_tx, salida_rx = anyio.create_memory_object_stream(64)

    def dump(sm):
        return sm.message.model_dump(by_alias=True, exclude_none=True, mode="json")

    async def bombear_entrada():
        async with entrada_tx:
            async for sm in read:
                if not isinstance(sm, Exception):
                    d = dump(sm)
                    reg("MCP ←", una_linea(d), d)
                await entrada_tx.send(sm)

    async def bombear_salida():
        async with salida_rx:
            async for sm in salida_rx:
                d = dump(sm)
                reg("MCP →", una_linea(d), d)
                await write.send(sm)

    return entrada_rx, salida_tx, bombear_entrada, bombear_salida


def herramientas_para_el_modelo(tools) -> list:
    """De tools/list (formato MCP) al formato de tool calling que recibe el modelo."""
    return [{"type": "function", "function": {"name": t.name, "description": t.description or "",
                                               "parameters": t.inputSchema}} for t in tools]


@asynccontextmanager
async def sesion_mcp(script, reg: Registro, cliente: str, env: dict | None = None, log_servidor=None):
    """Lanza el servidor MCP (script de Python) como otro proceso y entrega una sesión ya inicializada."""
    servidor = StdioServerParameters(command=sys.executable, args=[str(script)], cwd=str(script.parent),
                                     env={**os.environ, **(env or {}), "PYTHONIOENCODING": "utf-8"})
    reg("INFO", f"lanzo el servidor MCP como otro proceso: python {script.name} (transporte stdio)")
    async with stdio_client(servidor, errlog=log_servidor or sys.stderr) as (read, write):
        rx, tx, entrada, salida = intercalar_registro(read, write, reg)
        async with anyio.create_task_group() as tg:
            tg.start_soon(entrada)
            tg.start_soon(salida)
            async with ClientSession(rx, tx, client_info=Implementation(name=cliente, version="1.0")) as session:
                await session.initialize()
                yield session
            tg.cancel_scope.cancel()


async def llamar(session, nombre: str, argumentos: dict) -> tuple[str, bool]:
    """tools/call: devuelve el texto de la respuesta y si el servidor la marcó como error."""
    res = await session.call_tool(nombre, argumentos)
    return "".join(getattr(c, "text", "") for c in res.content), bool(res.isError)
