"""Pruebas funcionales: el parche debe corregir la falla SIN romper lo que la API ya hacía.

Por defecto prueban app_andina/; el escalón 3 las corre sobre la versión parchada con APP_DIR.
"""
import importlib.util
import os
import pathlib
import sys

import pytest

APP_DIR = pathlib.Path(os.environ.get("APP_DIR", pathlib.Path(__file__).resolve().parent.parent / "app_andina"))


@pytest.fixture(scope="module")
def cliente():
    sys.path.insert(0, str(APP_DIR))
    spec = importlib.util.spec_from_file_location("app_bajo_prueba", APP_DIR / "app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.app.config["TESTING"] = True
    return mod.app.test_client()


def test_buscar_por_ciudad(cliente):
    r = cliente.get("/comercios/buscar?ciudad=Lima")
    assert r.status_code == 200
    assert [c["nombre"] for c in r.get_json()] == ["Bodega San Martín"]


def test_buscar_ciudad_sin_comercios(cliente):
    assert cliente.get("/comercios/buscar?ciudad=Cusco").get_json() == []


def test_ver_pago_propio(cliente):
    r = cliente.get("/pagos/10", headers={"X-Comercio-Id": "1"})
    assert r.status_code == 200
    assert r.get_json()["monto"] == 125.50
    assert r.get_json()["tarjeta"].endswith("1111")


def test_pago_inexistente(cliente):
    assert cliente.get("/pagos/999", headers={"X-Comercio-Id": "1"}).status_code == 404


def test_importar_config_simple(cliente):
    r = cliente.post("/config/importar", data="moneda: PEN\nlimite: 500\n")
    assert r.get_json()["claves"] == ["limite", "moneda"]


def test_login_con_clave_correcta(cliente):
    # Las claves ya guardadas deben seguir funcionando: un cambio de algoritmo sin migración rompe esta prueba
    r = cliente.post("/login", json={"comercio_id": 1, "clave": "password"})
    assert r.status_code == 200 and r.get_json()["ok"] is True


def test_login_con_clave_incorrecta(cliente):
    assert cliente.post("/login", json={"comercio_id": 1, "clave": "otra"}).status_code == 401


def test_salud(cliente):
    assert cliente.get("/salud").get_json()["estado"] == "ok"
