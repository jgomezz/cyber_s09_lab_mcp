"""Demo 2 · El mismo protocolo con el SDK oficial de MCP, y lo que recibe el modelo.

Ahora el cliente es el SDK (mcp.ClientSession): hace initialize, tools/list y tools/call por nosotros. El
registro muestra cada mensaje que pasa por debajo (MCP → y MCP ←), igual que en la demo 1.
Luego se muestra la traducción de tools/list al formato de "tool calling" que entiende el modelo:
esa lista, con sus descripciones, es TODO lo que el modelo sabe de las herramientas.

Uso:
  python demo_2_cliente.py
  python demo_2_cliente.py --detalle 2     # cada mensaje JSON completo
"""
import argparse
import asyncio
import json

from llm import BASE
from mcp_kit import Registro, herramientas_para_el_modelo, llamar, sesion_mcp


async def principal(detalle):
    reg = Registro(BASE / "salidas" / "demo_2.jsonl", detalle)
    async with sesion_mcp(BASE / "servidor_mcp.py", reg, "demo-sdk") as session:
        tools = (await session.list_tools()).tools
        formato_modelo = herramientas_para_el_modelo(tools)
        print("\nAsí recibe el modelo las herramientas (formato de tool calling):\n")
        print(json.dumps(formato_modelo[:2], ensure_ascii=False, indent=2))
        print(f"… y {len(formato_modelo) - 2} más. El modelo elige por el nombre y la DESCRIPCIÓN: quien escribe el servidor decide qué lee el modelo.\n")
        texto, error = await llamar(session, "auditar_dependencias", {})
        print("Resultado de auditar_dependencias:")
        for fila in json.loads(texto):
            print(f"  {fila['paquete']:<26} {fila['version']:<8} {fila['estado']:<28} {fila['detalle'][:60]}")
    reg.cerrar()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--detalle", type=int, choices=[1, 2], default=1)
    asyncio.run(principal(ap.parse_args().detalle))
