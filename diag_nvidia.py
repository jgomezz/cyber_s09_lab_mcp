"""Diagnóstico de la API de NVIDIA (build.nvidia.com).

Uso:
  python diag_nvidia.py                         # prueba el modelo de config.yaml
  python diag_nvidia.py openai/gpt-oss-120b     # prueba otro modelo del catálogo

Revisa: 1) formato de la clave, 2) si la clave sirve para listar modelos, 3) si el modelo está en la
lista del endpoint gratuito y 4) una consulta real al modelo, mostrando el error tal como lo entrega NVIDIA.
"""
import os
import sys

import httpx

from llm import BASE, CONFIG  # carga .env

URL = "https://integrate.api.nvidia.com/v1"


def pedir(metodo, url, **kw):
    try:
        return httpx.request(metodo, url, **kw)
    except httpx.HTTPError as e:
        raise SystemExit(f"   Sin conexión con NVIDIA ({type(e).__name__}: {e}). Revisen la red o el proxy de su organización.")


def main():
    clave_cruda = os.getenv("NVIDIA_API_KEY", "")
    clave = clave_cruda.strip().strip('"').strip("'")
    modelo = sys.argv[1] if len(sys.argv) > 1 else CONFIG["providers"]["nvidia"]["model"].removeprefix("openai/")
    print(f"Modelo a probar: {modelo}\n")

    print("1) Formato de la clave")
    if not clave:
        return print("   FALLA: no hay NVIDIA_API_KEY en .env")
    print(f"   largo {len(clave)} · empieza con '{clave[:6]}' · termina con '...{clave[-4:]}'")
    if clave != clave_cruda:
        print("   ATENCIÓN: la clave en .env tiene espacios o comillas alrededor. Déjenla así: NVIDIA_API_KEY=nvapi-...")
    if not clave.startswith("nvapi-"):
        print("   ATENCIÓN: las claves del catálogo empiezan con 'nvapi-'. Generen una desde la página del modelo en build.nvidia.com (botón 'Get API Key').")

    cab = {"Authorization": f"Bearer {clave}", "Accept": "application/json"}
    print("\n2) ¿La clave sirve para listar modelos?")
    r = pedir("GET", f"{URL}/models", headers=cab, timeout=30)
    print(f"   HTTP {r.status_code}")
    ids = [m["id"] for m in r.json().get("data", [])] if r.status_code == 200 else []

    print("\n3) ¿El modelo está en la lista del endpoint gratuito?")
    if ids:
        print(f"   {'SÍ' if modelo in ids else 'NO'} ({len(ids)} modelos disponibles)")
        if modelo not in ids:
            parecidos = [i for i in ids if modelo.split('/')[-1].split('-')[0] in i][:8]
            print(f"   Parecidos: {', '.join(parecidos) or 'ninguno'}")

    print("\n4) Consulta real al modelo")
    r = pedir("POST", f"{URL}/chat/completions", headers={**cab, "Content-Type": "application/json"}, timeout=60,
                   json={"model": modelo, "messages": [{"role": "user", "content": "Responde solo: listo"}], "max_tokens": 20})
    print(f"   HTTP {r.status_code}: {r.text[:300]}")
    if r.status_code == 200:
        print("\nTodo bien: usen este modelo en config.yaml como  model: openai/" + modelo)
    elif r.status_code == 401 and "JWT" in r.text:
        print("\nEl modelo no acepta esta clave en el endpoint gratuito (suele pasar con modelos sin 'Free Endpoint' o deprecados).")
        print("Prueben un modelo que esté en la lista del paso 3, o generen la clave desde la página de ese modelo.")
    elif r.status_code in (401, 403):
        print("\nClave rechazada: generen una nueva en build.nvidia.com y péguenla en .env sin comillas ni espacios.")
    elif r.status_code == 404:
        print("\nEl modelo no existe con ese nombre en el endpoint gratuito: copien el id exacto del paso 3.")


if __name__ == "__main__":
    main()
