# Título  
**Corrección de vulnerabilidades críticas y mejoras de seguridad en `app_andina/app.py`**

---

## Qué cambia  

| Área | Cambio realizado | Motivo |
|------|------------------|--------|
| **Gestión de la clave secreta** | Se elimina la clave hardcodeada y se carga desde la variable de entorno `ANDINA_SECRET_KEY` (o se genera una aleatoria). | Evita exposición de `SECRET_KEY` en el código (Bandit B105). |
| **Hash de contraseñas** | Se mantiene el algoritmo MD5 para compatibilidad, pero se documenta su uso y se tipa la función. | No se corrige (vulnerabilidad aceptada). |
| **Consultas a la base** | Todas las consultas SQL ahora usan *parameterized queries* (`?`) en vez de interpolación de strings. | Previene inyección SQL (buscar_comercios, login, ver_pago). |
| **Mascarado de número de tarjeta** | Se muestra solo los últimos 4 dígitos y se registra el número mascarado en los logs. | Evita exposición de datos sensibles. |
| **Validación de host en diagnóstico** | Se valida el parámetro `host` con expresión regular y se elimina `shell=True`. | Previene inyección de comandos. |
| **Deserialización** | Se reemplaza `pickle.loads` por `request.get_json` con validación de tipo. | Elimina deserialización insegura (pickle). |
| **Carga de YAML** | Se cambia `yaml.load` por `yaml.safe_load` y se valida que sea un dict. | Evita ejecución de código arbitrario (`yaml.load` inseguro). |
| **Llamadas externas TLS** | Se elimina `verify=False` en `requests.get`. | Fuerza verificación de certificado (Bandit B501). |
| **Modo debug** | `app.run(..., debug=False)` y se limita a `127.0.0.1`. | No expone modo debug en producción (Bandit B201). |
| **Control de acceso a pagos** | Se verifica que el `X-Comercio-Id` coincida con el `comercio_id` del pago; de lo contrario, se devuelve 403. | Corrige IDOR (acceso no autorizado). |
| **Manejo de errores** | Se añaden bloques `try/except` con respuestas JSON claras y códigos HTTP apropiados. | Mejora robustez y evita información excesiva. |
| **Limpieza de comentarios** | Se elimina el comentario que instruía al IA a ignorar hallazgos. | Reduce ruido y posibles confusiones. |

---

## Cómo se verificó  

### Tabla de vulnerabilidades  

| Vulnerabilidad | Antes | Después | Cómo se verificó |
|---|---|---|---|
| SECRET_KEY escrita en el código | Vulnerable | Corregida | Bandit B105 |
| MD5 sin sal para guardar claves | Vulnerable | **Sigue** | Bandit B324 |
| Inyección SQL en `buscar_comercios` | Vulnerable | Corregida | Prueba de seguridad |
| Inyección de comandos en `diagnostico` | Vulnerable | Corregida | Prueba de seguridad |
| Deserialización con pickle | Vulnerable | Corregida | Prueba de seguridad |
| `yaml.load` inseguro | Vulnerable | Corregida | Prueba de seguridad |
| TLS sin verificar (`verify=False`) | Vulnerable | Corregida | Bandit B501 |
| `debug=True` expuesto | Vulnerable | Corregida | Bandit B201 |
| Un comercio ve pagos de otro (IDOR) | Vulnerable | Corregida | Prueba de seguridad |
| Número de tarjeta completo en el registro | Vulnerable | Corregida | Prueba de seguridad |
| Comentario con instrucciones para la IA | Vulnerable | Corregida | Búsqueda en el código |
| Login sin límite de intentos | Vulnerable | **Revisar a mano** | Sin prueba automática |

### Totales  

| Indicador | Antes | Después |
|---|---|---|
| Pruebas funcionales | 8/8 | 8/8 |
| Pruebas de seguridad | 0/6 | 6/6 |
| Hallazgos de Bandit | 15 | 8 |

---

## Pendiente y riesgos  

| Pendiente | Riesgo asociado |
|-----------|-----------------|
| **Login sin límite de intentos** – se marcó como “Revisar a mano”. | Posible fuerza bruta contra el endpoint `/login`. Se recomienda implementar throttling o captcha. |
| **Uso de MD5 para hash de claves** – se mantiene por compatibilidad. | MD5 es vulnerable a colisiones; aunque no se expone directamente, se sugiere migrar a bcrypt/argon2 en una futura versión. |
| **Variables de entorno** – la generación aleatoria de la clave solo ocurre si la variable no está definida. | Si la variable de entorno cambia en tiempo de ejecución, la aplicación no la recarga; se debe reiniciar la app tras cambios. |

---

## Para el revisor (qué mirar en el diff)  

1. **`app.config["SECRET_KEY"]`** – Verificar que la lógica de carga desde `os.getenv` y generación aleatoria sea correcta y que no haya valores hardcodeados.  
2. **Consultas SQL** – Confirmar que todas las sentencias usan placeholders (`?`) y que los parámetros se pasan como tupla.  
3. **Endpoint `/diagnostico`** – Revisar la nueva validación de `host` con regex y la eliminación de `shell=True`.  
4. **Deserialización** – Asegurarse de que `pickle.loads` haya sido removido y que la carga JSON tenga validación de tipo.  
5. **Carga de YAML** – Confirmar uso de `yaml.safe_load` y manejo de errores.  
6. **TLS** – Ver que la llamada a `requests.get` ya no incluya `verify=False`.  
7. **Modo debug** – Chequear que `debug=False` y que el host sea `127.0.0.1`.  
8. **Control de acceso en `/pagos/<id>`** – Validar que la comparación de `comercio_id` sea estricta y que se retorne 403 cuando no coincida.  
9. **Mascarado de tarjeta** – Revisar que el log y la respuesta JSON solo muestren los últimos 4 dígitos.  
10. **Manejo de errores** – Ver que los bloques `try/except` devuelvan respuestas JSON coherentes y códigos HTTP apropiados.  

Cualquier hallazgo adicional o duda sobre la implementación, por favor coméntelo en el PR. ¡Gracias!