"""Demo 1 · MCP por dentro: el protocolo a mano, sin SDK de cliente y sin modelo.

Este script lanza servidor_mcp.py como otro proceso y le escribe mensajes JSON-RPC, uno por línea, por su
entrada estándar. Lee las respuestas por su salida estándar. Es exactamente lo que hace cualquier cliente MCP
(Claude Desktop, un IDE, un agente): no hay nada más debajo.

  1. initialize                 el cliente se presenta y acuerdan la versión del protocolo
  2. notifications/initialized  el cliente avisa que está listo (notificación: no tiene id ni respuesta)
  3. tools/list                 qué herramientas hay, con su descripción y su esquema de argumentos
  4. tools/call                 llamar una herramienta con argumentos
  5. tools/call con una ruta fuera de la aplicación: el servidor la rechaza

Uso:
  python demo_1_protocolo.py            # pausa entre pasos (Enter para seguir)
  python demo_1_protocolo.py --seguido  # sin pausas
"""
import argparse
import json
import subprocess
import sys
import threading
from pathlib import Path

BASE = Path(__file__).resolve().parent
CIAN, AMARILLO, GRIS, FIN = ("\033[36m", "\033[33m", "\033[90m", "\033[0m") if sys.stdout.isatty() else ("", "", "", "")


def mostrar(titulo, mensaje, color, recorte=1800):
    s = json.dumps(mensaje, ensure_ascii=False, indent=2)
    if len(s) > recorte:
        s = s[:recorte] + "\n  … (recortado en pantalla)"
    print(f"{color}{titulo}\n{s}{FIN}\n", flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seguido", action="store_true")
    args = ap.parse_args()
    pausa = (lambda t: None) if args.seguido else (lambda t: input(f"{GRIS}── Enter para {t}{FIN}"))

    proc = subprocess.Popen([sys.executable, str(BASE / "servidor_mcp.py")], cwd=BASE, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, encoding="utf-8", bufsize=1, env={**__import__("os").environ, "PYTHONIOENCODING": "utf-8"})

    def leer_stderr():
        for linea in proc.stderr:
            print(f"{GRIS}{linea.rstrip()}{FIN}", flush=True)
    threading.Thread(target=leer_stderr, daemon=True).start()

    def enviar(mensaje, espera_respuesta=True):
        mostrar("CLIENTE → SERVIDOR (una línea por stdin)", mensaje, CIAN)
        proc.stdin.write(json.dumps(mensaje, ensure_ascii=False) + "\n")
        proc.stdin.flush()
        if not espera_respuesta:
            return None
        respuesta = json.loads(proc.stdout.readline())
        mostrar("SERVIDOR → CLIENTE (una línea por stdout)", respuesta, AMARILLO)
        return respuesta

    print(f"Lancé el servidor: python servidor_mcp.py (proceso {proc.pid}). Su registro sale en gris con el prefijo [servidor].\n")
    pausa("enviar initialize")
    enviar({"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "demo-a-mano", "version": "1.0"}}})
    pausa("enviar notifications/initialized")
    enviar({"jsonrpc": "2.0", "method": "notifications/initialized"}, espera_respuesta=False)
    print("(una notificación no tiene id: el servidor no responde)\n")
    pausa("pedir la lista de herramientas (tools/list)")
    lista = enviar({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    print("Resumen de tools/list (esto es lo que el modelo verá como herramientas):")
    for t in lista["result"]["tools"]:
        args_ = ", ".join(t["inputSchema"].get("properties", {})) or "sin argumentos"
        print(f"  · {t['name']}({args_}): {t['description'][:90]}")
    print()
    pausa("llamar leer_codigo(app.py, líneas 84 a 89)")
    enviar({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "leer_codigo", "arguments": {"archivo": "app.py", "desde": 84, "hasta": 89}}})
    print("Fíjense en las líneas 84-85: un comentario dirigido al revisor automático. Para el servidor es solo texto;\n"
          "el riesgo aparece cuando ese texto llega a un modelo (LLM01).\n")
    pausa("llamar analizar_bandit()")
    r = enviar({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "analizar_bandit", "arguments": {}}}, )
    hallazgos = json.loads(r["result"]["content"][0]["text"])
    print(f"Bandit devolvió {len(hallazgos)} hallazgos. Los de severidad HIGH:")
    for x in hallazgos:
        if x["severidad"] == "HIGH":
            print(f"  línea {x['linea']:>3}  {x['regla']}  {x['cwe']}  {x['mensaje'][:70]}")
    print()
    pausa("intentar leer un archivo fuera de la aplicación (../.env)")
    enviar({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "leer_codigo", "arguments": {"archivo": "../.env"}}})
    print("El servidor valida la ruta: aunque el modelo (o un atacante) pida otro archivo, la herramienta solo lee la aplicación.\n"
          "Ese control vive en el servidor y no depende de lo que diga el prompt.")
    proc.stdin.close()
    proc.wait(timeout=10)


if __name__ == "__main__":
    main()
