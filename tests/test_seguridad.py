"""Pruebas de seguridad: fallan en la versión original y deberían pasar después de los parches."""
import logging
import pickle

from test_app import cliente  # noqa: F401  (reutiliza el fixture)


def test_inyeccion_sql_no_devuelve_todo(cliente):  # noqa: F811
    r = cliente.get("/comercios/buscar?ciudad=' OR '1'='1")
    assert r.get_json() == []


def test_no_ve_pago_de_otro_comercio(cliente):  # noqa: F811
    r = cliente.get("/pagos/11", headers={"X-Comercio-Id": "1"})
    assert r.status_code in (403, 404)


def test_diagnostico_rechaza_comandos(cliente):  # noqa: F811
    r = cliente.get("/diagnostico?host=127.0.0.1;id")
    assert r.status_code == 400


def test_yaml_no_crea_objetos(cliente):  # noqa: F811
    r = cliente.post("/config/importar", data="!!python/object/apply:os.getcwd []")
    assert r.status_code >= 400


def test_preferencias_no_deserializa_pickle(cliente):  # noqa: F811
    # La carga es inofensiva (un diccionario); lo que se prueba es que la API no acepte pickle
    r = cliente.post("/preferencias", data=pickle.dumps({"tema": "verde"}))
    assert r.status_code == 400


def test_registro_no_guarda_tarjeta_completa(cliente, caplog):  # noqa: F811
    with caplog.at_level(logging.INFO):
        cliente.get("/pagos/10", headers={"X-Comercio-Id": "1"})
    assert "4111111111111111" not in caplog.text
