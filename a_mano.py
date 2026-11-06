"""Laboratorio · Ejercicio 1: la revisión como se hace hoy, sin IA.

Ejecuta Bandit sobre la API de comercios y muestra cada alerta con su código, una por una, como la vería un
desarrollador o un analista de AppSec. Con --pruebas, muestra además qué pruebas fallan hoy.

Uso:
  python a_mano.py               # las alertas de Bandit con el código
  python a_mano.py --pausa       # una alerta a la vez (Enter para seguir)
  python a_mano.py --pruebas     # además, las pruebas funcionales y de seguridad de la versión original
"""
import argparse
import sys
import time
from collections import Counter

from herramientas import BASE, bandit, pruebas_detalle

APP = BASE / "app_andina"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pausa", action="store_true", help="una alerta a la vez")
    ap.add_argument("--pruebas", action="store_true", help="mostrar también las pruebas de la versión original")
    args = ap.parse_args()
    lineas = (APP / "app.py").read_text(encoding="utf-8").splitlines()
    t0 = time.time()
    alertas = sorted(bandit(APP), key=lambda x: ({"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(x["severidad"], 3), x["linea"]))
    print(f"Bandit sobre app_andina/: {len(alertas)} alertas en {time.time() - t0:.1f} s\n")
    for i, a in enumerate(alertas, 1):
        n = a["linea"]
        print(f"── Alerta {i}/{len(alertas)} · {a['regla']} · severidad {a['severidad']} · {a['cwe']} · línea {n}")
        print(f"   {a['mensaje']}")
        for k in range(max(1, n - 1), min(len(lineas), n + 1) + 1):
            print(f"   {'→' if k == n else ' '} {k:>4}  {lineas[k - 1]}")
        print("   ¿Real o falso positivo? ¿Qué tan grave para una API de pagos? ¿Cómo se corrige?\n")
        if args.pausa:
            input("   (Enter para la siguiente) ")
    if args.pruebas:
        p = pruebas_detalle(APP)
        print("Pruebas de la versión original:")
        for k, v in p.items():
            print(f"   {'pasa ' if v['ok'] else 'FALLA'}  {v['tipo']:<10} {k}")
        print()
    sev = Counter(a["severidad"] for a in alertas)
    print("═" * 92)
    print(f"  A MANO: {len(alertas)} alertas ({sev['HIGH']} altas, {sev['MEDIUM']} medias, {sev['LOW']} bajas) en {len(set(a['regla'] for a in alertas))} reglas distintas.")
    print("  Y todavía falta: decidir cuáles son reales, buscar lo que Bandit no ve (permisos, datos sensibles en")
    print("  el registro, límites de intentos), corregir sin romper la API, probar y escribir el pull request.")
    print("  ¿Cuánto les tomaría? Tómenle el tiempo en el ejercicio 1 y compárenlo con:  python revisor.py")
    print("═" * 92)


if __name__ == "__main__":
    sys.exit(main())
