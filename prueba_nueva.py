"""Laboratorio · La prueba que falta, escrita por IA.

remediar.py dejó una vulnerabilidad en «Revisar a mano»: el login no tiene límite de intentos (fuerza bruta).
No había prueba automática para eso. Este programa:

  1. Le pide a la IA una prueba de pytest que demuestre la falla (después de 5 intentos fallidos, el sexto se rechaza con 429).
  2. La ejecuta sobre la versión ORIGINAL: tiene que FALLAR. Si pasa, la prueba no sirve (no detecta nada).
  3. La ejecuta sobre la versión CORREGIDA por remediar.py (si existe): muestra que la falla sigue ahí.
  4. Con --corregir: la IA agrega el límite de intentos y se ejecutan TODAS las pruebas (funcionales, de seguridad
     y la nueva) sobre una copia. Así la vulnerabilidad pasa de «Revisar a mano» a «verificada por una prueba».

Uso:
  python prueba_nueva.py --proveedor ollama_cloud
  python prueba_nueva.py --corregir
  python prueba_nueva.py --simulado [--corregir]

Resultados: salidas/prueba_nueva/test_login_limite.py y, con --corregir, salidas/prueba_nueva/app_andina/app.py
"""
import argparse
import re
import shutil
import sys
import time

from herramientas import BASE, _correr
from llm import chat
from remediar import extraer_codigo

DESTINO = BASE / "salidas" / "prueba_nueva"
ORIGINAL = BASE / "app_andina"
CORREGIDA = BASE / "salidas" / "remediacion" / "app_andina"
TEST = DESTINO / "test_login_limite.py"

SISTEMA_PRUEBA = """Eres desarrollador senior de Python especializado en pruebas de seguridad.
Escribes pruebas de pytest cortas, legibles y deterministas. Responde con el archivo completo dentro de un único bloque
```python ... ```, sin explicaciones."""

PEDIDO_PRUEBA = """Escribe un archivo de pytest que demuestre que el login de esta API de Flask no tiene límite de intentos.

Reglas:
- Importa el fixture así:  from test_app import cliente  # noqa: F401   (ya existe; entrega un test_client de Flask)
- Usa el comercio_id 2 (no uses el 1: lo usan otras pruebas).
- Haz 5 intentos con una clave incorrecta (cada uno responde 401) y después un sexto intento: debe responder 429.
- Una sola función de prueba llamada test_login_bloquea_tras_intentos_fallidos(cliente), con un docstring de una línea.

Así es el login hoy:
```python
{login}
```"""

SISTEMA_FIX = """Eres desarrollador senior de Python/Flask especializado en seguridad. Corriges sin cambiar rutas ni el formato
de las respuestas y sin agregar dependencias. Responde con el archivo app.py COMPLETO dentro de un único bloque
```python ... ```, sin explicaciones."""

PEDIDO_FIX = """Agrega a esta API un límite de intentos de login: después de 5 intentos fallidos para un mismo comercio_id,
/login responde 429 con {{"ok": false, "error": "demasiados intentos"}}. Un login correcto reinicia el contador.
Usa un diccionario en memoria (es un laboratorio). No cambies nada más.

Esta prueba tiene que pasar, y también las pruebas que ya existían:
```python
{prueba}
```

Archivo app.py:
```python
{app}
```"""

SIM_PRUEBA = '''"""Prueba nueva (escrita por IA): el login debe bloquear después de 5 intentos fallidos."""
from test_app import cliente  # noqa: F401


def test_login_bloquea_tras_intentos_fallidos(cliente):  # noqa: F811
    """Después de 5 claves incorrectas, el sexto intento se rechaza con 429."""
    for _ in range(5):
        r = cliente.post("/login", json={"comercio_id": 2, "clave": "incorrecta"})
        assert r.status_code == 401
    r = cliente.post("/login", json={"comercio_id": 2, "clave": "incorrecta"})
    assert r.status_code == 429, "el login no tiene límite de intentos: permite fuerza bruta"
'''


def sim_fix(app: str) -> str:
    app = app.replace('@app.route("/login", methods=["POST"])',
                      'INTENTOS_FALLIDOS = {}\nMAX_INTENTOS = 5\n\n\n@app.route("/login", methods=["POST"])', 1)
    app = re.sub(r'(    datos = request\.get_json\(force=True\)\n)(    fila = conexion\(\)\.execute\("SELECT id, clave_hash FROM comercios WHERE id = \?", \(datos\.get\("comercio_id"\),\)\)\.fetchone\(\)\n)',
                 r'\1    cid = datos.get("comercio_id")\n    if INTENTOS_FALLIDOS.get(cid, 0) >= MAX_INTENTOS:\n        return jsonify(ok=False, error="demasiados intentos"), 429\n\2', app, count=1)
    app = app.replace("        return jsonify(ok=True, comercio_id=fila[0])\n    return jsonify(ok=False), 401",
                      "        INTENTOS_FALLIDOS.pop(cid, None)\n        return jsonify(ok=True, comercio_id=fila[0])\n"
                      "    INTENTOS_FALLIDOS[cid] = INTENTOS_FALLIDOS.get(cid, 0) + 1\n    return jsonify(ok=False), 401", 1)
    return app


def funcion_login(app: str) -> str:
    m = re.search(r'@app\.route\("/login".*?(?=\n\n\n)', app, flags=re.S)
    return m.group(0) if m else app


def correr(carpeta, archivos) -> dict:
    """Ejecuta pytest (sin IA) sobre la versión indicada y devuelve {prueba: (ok, motivo)}."""
    r = _correr([sys.executable, "-m", "pytest", "-q", "-rA", "--no-header", "-p", "no:cacheprovider", "--tb=line", *map(str, archivos)],
                timeout=180, env={"APP_DIR": str(carpeta), "COLUMNS": "250", "PYTHONPATH": str(BASE / "tests")}, cwd=BASE)
    return {m.group(2): (m.group(1) == "PASSED", (m.group(3) or "")[:160])
            for m in re.finditer(r"^(PASSED|FAILED|ERROR) \S*::(\w+)(?: - (.*))?$", r.stdout, flags=re.M)}


def linea(titulo, res, esperado):
    ok, motivo = res.get("test_login_bloquea_tras_intentos_fallidos", (None, "la prueba no se pudo ejecutar"))
    estado = "pasa" if ok else ("falla" if ok is False else "error")
    marca = "✓" if (estado == esperado) else "✗"
    print(f"  {marca} {titulo:<46} la prueba {estado:<6} (esperado: {esperado})  {motivo if estado != 'pasa' else ''}")
    return estado


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--proveedor", help="proveedor de config.yaml")
    ap.add_argument("--corregir", action="store_true", help="además, la IA agrega el límite y se verifican todas las pruebas")
    ap.add_argument("--simulado", action="store_true", help="sin API: prueba y corrección simuladas")
    args = ap.parse_args()
    DESTINO.mkdir(parents=True, exist_ok=True)
    app_original = (ORIGINAL / "app.py").read_text(encoding="utf-8")

    t0 = time.time()
    print("1) La IA escribe la prueba que falta…")
    prueba = SIM_PRUEBA if args.simulado else extraer_codigo(
        chat(PEDIDO_PRUEBA.format(login=funcion_login(app_original)), provider=args.proveedor, system=SISTEMA_PRUEBA, temperature=0.1, timeout=180))
    TEST.write_text(prueba, encoding="utf-8")
    print(f"   {len(prueba.splitlines())} líneas en {time.time() - t0:.1f} s → salidas/prueba_nueva/test_login_limite.py\n")
    print("\n".join("   │ " + x for x in prueba.splitlines()))

    print("\n2) ¿La prueba detecta la falla? (pytest, sin IA)")
    linea("Versión original", correr(ORIGINAL, [TEST]), "falla")
    base_fix = ORIGINAL
    if (CORREGIDA / "app.py").exists():
        linea("Versión corregida por remediar.py", correr(CORREGIDA, [TEST]), "falla")
        base_fix = CORREGIDA
    else:
        print("    (no hay versión corregida: corran antes python remediar.py)")

    if args.corregir:
        print("\n3) La IA agrega el límite de intentos y se verifican TODAS las pruebas…")
        app_base = (base_fix / "app.py").read_text(encoding="utf-8")
        t1 = time.time()
        nuevo = sim_fix(app_base) if args.simulado else extraer_codigo(
            chat(PEDIDO_FIX.format(prueba=prueba, app=app_base), provider=args.proveedor, system=SISTEMA_FIX, temperature=0.1, timeout=300))
        copia = DESTINO / "app_andina"
        shutil.rmtree(copia, ignore_errors=True)
        shutil.copytree(ORIGINAL, copia, ignore=shutil.ignore_patterns("__pycache__"))
        (copia / "app.py").write_text(nuevo, encoding="utf-8")
        res = correr(copia, [BASE / "tests" / "test_app.py", BASE / "tests" / "test_seguridad.py", TEST])
        print(f"   corrección en {time.time() - t1:.1f} s → salidas/prueba_nueva/app_andina/app.py")
        estado = linea("Versión con límite de intentos", res, "pasa")
        otras = {k: v for k, v in res.items() if k != "test_login_bloquea_tras_intentos_fallidos"}
        rotas = [k for k, (ok, _) in otras.items() if not ok]
        print(f"    Pruebas que ya existían: {sum(ok for ok, _ in otras.values())}/{len(otras)} pasan" + (f" · fallan: {', '.join(rotas)}" if rotas else ""))
        if estado == "pasa" and not rotas:
            print("\n  «Login sin límite de intentos» pasa de «Revisar a mano» a «Corregida, verificada por una prueba».")
    print("\nLa prueba nueva queda como regresión: si alguien quita el límite, falla.")


if __name__ == "__main__":
    sys.exit(main())
