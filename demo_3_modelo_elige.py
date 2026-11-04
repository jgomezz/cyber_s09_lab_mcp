"""Demo 3 · El modelo elige qué herramienta llamar: el ciclo completo con registros.

Una pregunta concreta, el modelo con las herramientas del servidor y nada más. En pantalla:
  LLM →  lo que se le envía al modelo (mensajes y herramientas)
  LLM ←  lo que pide el modelo: una llamada a herramienta o la respuesta final
  MCP →  MCP ←  la llamada que hace el cliente al servidor y su respuesta
El modelo nunca ejecuta nada: pide, y el cliente decide si llama al servidor.

Uso:
  python demo_3_modelo_elige.py --proveedor groq
  python demo_3_modelo_elige.py --pregunta "¿Qué dependencias tienen vulnerabilidades?"
  python demo_3_modelo_elige.py --simulado
"""
import argparse
import asyncio
import json

from llm import BASE, CONFIG, chat_herramientas
from mcp_kit import Registro, herramientas_para_el_modelo, llamar, sesion_mcp

PREGUNTA = "¿Qué hallazgos de severidad alta reporta Bandit en app.py? Para cada uno, lee las líneas de código y dime si es un riesgo real."


class _L:
    def __init__(self, i, n, a):
        self.id, self.type = f"sim_{i}", "function"
        self.function = type("F", (), {"name": n, "arguments": json.dumps(a)})()


def simulado(mensajes):
    tools = [m for m in mensajes if m["role"] == "tool"]
    if not tools:
        return type("M", (), {"content": "", "tool_calls": [_L(0, "analizar_bandit", {})]})()
    if len(tools) == 1:
        altos = [x for x in json.loads(tools[0]["content"]) if x["severidad"] == "HIGH"]
        return type("M", (), {"content": "", "tool_calls": [_L(i + 1, "leer_codigo", {"archivo": "app.py", "desde": x["linea"] - 1, "hasta": x["linea"] + 1})
                                                             for i, x in enumerate(altos)]})()
    return type("M", (), {"content": "Bandit marca 4 hallazgos altos (líneas 41, 80, 100 y 105) y los cuatro son riesgos reales.", "tool_calls": None})()


async def principal(args):
    reg = Registro(BASE / "salidas" / "demo_3.jsonl", args.detalle)
    async with sesion_mcp(BASE / "servidor_mcp.py", reg, "demo-modelo") as session:
        herramientas = herramientas_para_el_modelo((await session.list_tools()).tools)
        mensajes = [{"role": "system", "content": "Eres revisor de código seguro. Usa las herramientas para responder con datos."},
                    {"role": "user", "content": args.pregunta}]
        enviados = 0
        for vuelta in range(1, args.max_vueltas + 1):
            reg("LLM →", f"vuelta {vuelta}: {len(mensajes) - enviados} mensaje(s) nuevo(s) + {len(herramientas)} herramientas", mensajes[enviados:])
            enviados = len(mensajes)
            msg = simulado(mensajes) if args.simulado else await asyncio.to_thread(chat_herramientas, mensajes, herramientas, args.proveedor)
            tcs = getattr(msg, "tool_calls", None) or []
            if not tcs:
                reg("LLM ←", "respuesta final", msg.content)
                print("\nRespuesta del modelo:\n" + (msg.content or ""))
                break
            reg("LLM ←", "pide: " + "; ".join(f"{t.function.name}({t.function.arguments})" for t in tcs))
            mensajes.append({"role": "assistant", "content": msg.content or "", "tool_calls": [
                {"id": t.id, "type": "function", "function": {"name": t.function.name, "arguments": t.function.arguments}} for t in tcs]})
            for t in tcs:
                texto, _ = await llamar(session, t.function.name, json.loads(t.function.arguments or "{}"))
                mensajes.append({"role": "tool", "tool_call_id": t.id, "name": t.function.name, "content": texto})
        else:
            reg("ALERTA", f"tope de {args.max_vueltas} vueltas alcanzado")
    reg.cerrar()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--proveedor")
    ap.add_argument("--pregunta", default=PREGUNTA)
    ap.add_argument("--max-vueltas", type=int, default=5)
    ap.add_argument("--detalle", type=int, choices=[1, 2], default=1)
    ap.add_argument("--simulado", action="store_true")
    a = ap.parse_args()
    a.proveedor = a.proveedor or CONFIG["default"]
    asyncio.run(principal(a))
