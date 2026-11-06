"""API de comercios de Andina Pagos (FICTICIA, con vulnerabilidades a propósito para el laboratorio).

No usar en producción. Cada falla está documentada en data/referencia_hallazgos.json.
"""
import hashlib
import json
import logging
import os
import random
import re
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)
# Cargar la clave secreta desde el entorno, o generar una aleatoria si no está definida.
app.config["SECRET_KEY"] = os.getenv("ANDINA_SECRET_KEY", os.urandom(24).hex())

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("api-comercios")

ETIQUETAS = {"usuario": "Usuario", "password": "Contraseña"}
DB = None

# Diccionario en memoria para controlar intentos fallidos de login por comercio_id
LOGIN_ATTEMPTS = {}

def conexion():
    global DB
    if DB is None:
        DB = sqlite3.connect(":memory:", check_same_thread=False)
        DB.executescript(
            """
            CREATE TABLE comercios (id INTEGER PRIMARY KEY, nombre TEXT, ciudad TEXT, clave_hash TEXT);
            CREATE TABLE pagos (id INTEGER PRIMARY KEY, comercio_id INTEGER, monto REAL, tarjeta TEXT);
            INSERT INTO comercios VALUES (1, 'Bodega San Martín', 'Lima', '5f4dcc3b5aa765d61d8327deb882cf99');
            INSERT INTO comercios VALUES (2, 'Farmacia Misti', 'Arequipa', 'e10adc3949ba59abbe56e057f20f883e');
            INSERT INTO pagos VALUES (10, 1, 125.50, '4111111111111111');
            INSERT INTO pagos VALUES (11, 2, 89.90, '5500000000000004');
            """
        )
    return DB


def hash_clave(clave: str) -> str:
    """Hash MD5 de la clave (compatibilidad con datos existentes)."""
    return hashlib.md5(clave.encode()).hexdigest()


@app.route("/salud")
def salud():
    color = random.choice(["verde", "azul"])
    version = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        capture_output=True,
        text=True,
    ).stdout.strip()
    return jsonify(estado="ok", tema=color, version=version or "desconocida")


@app.route("/comercios/buscar")
def buscar_comercios():
    ciudad = request.args.get("ciudad", "")
    filas = conexion().execute(
        "SELECT id, nombre, ciudad FROM comercios WHERE ciudad = ?", (ciudad,)
    ).fetchall()
    return jsonify([{"id": f[0], "nombre": f[1], "ciudad": f[2]} for f in filas])


@app.route("/login", methods=["POST"])
def login():
    datos = request.get_json(force=True)
    comercio_id = datos.get("comercio_id")
    # Verificar bloqueo por intentos fallidos
    if comercio_id is not None:
        intentos = LOGIN_ATTEMPTS.get(comercio_id, 0)
        if intentos >= 5:
            return jsonify(ok=False, error="demasiados intentos"), 429

    fila = conexion().execute(
        "SELECT id, clave_hash FROM comercios WHERE id = ?", (comercio_id,)
    ).fetchone()
    if fila and fila[1] == hash_clave(datos.get("clave", "")):
        # Login exitoso: reiniciar contador
        if comercio_id is not None and comercio_id in LOGIN_ATTEMPTS:
            del LOGIN_ATTEMPTS[comercio_id]
        return jsonify(ok=True, comercio_id=fila[0])
    # Login fallido: incrementar contador
    if comercio_id is not None:
        LOGIN_ATTEMPTS[comercio_id] = LOGIN_ATTEMPTS.get(comercio_id, 0) + 1
    return jsonify(ok=False), 401


@app.route("/pagos/<int:pago_id>")
def ver_pago(pago_id):
    comercio = request.headers.get("X-Comercio-Id")
    fila = conexion().execute(
        "SELECT id, comercio_id, monto, tarjeta FROM pagos WHERE id = ?", (pago_id,)
    ).fetchone()
    if not fila:
        return jsonify(error="no existe"), 404
    if str(fila[1]) != str(comercio):
        return jsonify(error="no autorizado"), 403
    tarjeta_mascarada = "**** " + fila[3][-4:]
    log.info(
        "Consulta de pago %s del comercio %s con tarjeta %s",
        pago_id,
        comercio,
        tarjeta_mascarada,
    )
    return jsonify(id=fila[0], comercio_id=fila[1], monto=fila[2], tarjeta=tarjeta_mascarada)


@app.route("/diagnostico")
def diagnostico():
    host = request.args.get("host", "127.0.0.1")
    if not re.fullmatch(r"[a-zA-Z0-9.\-]+", host):
        return jsonify(error="host inválido"), 400
    salida = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True,
        text=True,
    )
    return jsonify(codigo=salida.returncode)


@app.route("/preferencias", methods=["POST"])
def cargar_preferencias():
    try:
        prefs = request.get_json(force=True)
        if not isinstance(prefs, (list, dict)):
            raise ValueError
        count = len(prefs)
        return jsonify(recibidas=count)
    except Exception:
        return jsonify(error="formato no soportado"), 400


@app.route("/config/importar", methods=["POST"])
def importar_config():
    try:
        cfg = yaml.safe_load(request.get_data(as_text=True))
        if not isinstance(cfg, dict):
            raise ValueError
        return jsonify(claves=sorted(cfg))
    except Exception:
        return jsonify(error="YAML inválido"), 400


@app.route("/tipo-cambio")
def tipo_cambio():
    try:
        r = requests.get(
            "https://api.andinapagos.example/tipo-cambio",
            timeout=5,
        )
        r.raise_for_status()
        return jsonify(r.json())
    except Exception:
        return jsonify(error="no disponible"), 502


if __name__ == "__main__":
    # Ejecutar la aplicación solo en localhost y sin modo debug.
    app.run(host="127.0.0.1", port=5000, debug=False)
