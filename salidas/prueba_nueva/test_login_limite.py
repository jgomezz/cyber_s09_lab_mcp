from test_app import cliente  # noqa: F401

def test_login_bloquea_tras_intentos_fallidos(cliente):
    """Verifica que después de 5 intentos fallidos el sexto devuelve 429."""
    payload = {"comercio_id": 2, "clave": "clave_incorrecta"}

    for _ in range(5):
        resp = cliente.post("/login", json=payload)
        assert resp.status_code == 401

    resp = cliente.post("/login", json=payload)
    assert resp.status_code == 429
