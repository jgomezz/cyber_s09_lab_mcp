# Clase 9 · Revisión de código seguro con IA sobre MCP

La API de comercios de Andina Pagos (`app_andina/app.py`) tiene fallas a propósito. Un revisor con IA la revisa
usando herramientas publicadas por un servidor MCP (Bandit, Semgrep y pip-audit), y ustedes encienden uno a uno
los controles que vuelven confiable ese flujo.

## Preparación (antes de la clase)

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-opcional.txt   # Semgrep (opcional; en Windows, desde WSL si falla)
cp .env.example .env                 # y completen sus claves
python check_env.py                  # al menos dos proveedores en la nube deben responder
python revisor.py --simulado --controles ninguno --sin-parche   # prueba el flujo sin gastar API
```

## Archivos

| Archivo | Qué es |
| --- | --- |
| `app_andina/` | La aplicación que se revisa (no se modifica: los parches van a `salidas/`) |
| `herramientas.py` | Bandit, Semgrep, pip-audit, PyPI y las pruebas, sin IA |
| `servidor_mcp.py` | Servidor MCP que publica esas herramientas (solo lectura) |
| `mcp_kit.py` | Cliente MCP y registro de todo lo que pasa por debajo |
| `controles.py` | Los controles C1 a C4 |
| `revisor.py` | El laboratorio: revisor con IA + controles + comparación con la referencia |
| `demo_1_protocolo.py` … `demo_3_modelo_elige.py` | Los scripts de la demo del profesor |
| `ataques/` | Desafíos extra: dos ataques que se corren sin y con controles |
| `comparar.py` | Opcional: compara modelos y combinaciones de controles |
| `data/referencia_hallazgos.json` | La referencia del profesor (16 fallas) |

## Demo (la hace el profesor; pueden repetirla)

```bash
python demo_1_protocolo.py               # JSON-RPC a mano: initialize, tools/list, tools/call
python demo_2_cliente.py                 # lo mismo con el SDK, y lo que recibe el modelo
python demo_3_modelo_elige.py --proveedor ollama_cloud   # el modelo elige qué herramienta llamar
```

## Laboratorio

**Parte 1 · Sin controles**

```bash
python revisor.py --proveedor ollama_cloud --controles ninguno
```

**Parte 2 · Activar los controles, de a uno**

```bash
python revisor.py --proveedor ollama_cloud --controles C1 --sin-parche
python revisor.py --proveedor ollama_cloud --controles C1,C2 --sin-parche
python revisor.py --proveedor ollama_cloud --controles C1,C2,C3
```

| Control | Riesgo | Qué hace |
| --- | --- | --- |
| C1 | LLM01 Inyección de prompt | Marca el código y los resultados como datos no confiables y elimina comentarios con instrucciones |
| C2 | LLM07 Desinformación | Verifica cada hallazgo contra el código y las herramientas; agrega lo que el modelo omitió |
| C3 | LLM10 Manejo inadecuado de la salida | Acepta el parche solo si pasa las pruebas y no empeora Bandit |
| C4 (opcional) | LLM04 Cadena de suministro | Verifica en PyPI cada paquete antes de aceptarlo |

Las líneas `CTRL` del registro muestran qué hizo cada control. El detalle queda en `salidas/revision_*.xlsx`.

## Desafíos y opcionales

```bash
python ataques/ataque_1_comentario.py --proveedor ollama_cloud   # inyección con otra redacción
python ataques/ataque_2_paquete.py --proveedor ollama_cloud      # paquete que no existe
python revisor.py --proveedor groq --controles todos             # C4 y otro modelo
python comparar.py                                               # todas las corridas en una tabla
```

## Proveedores

Ollama Cloud (`ollama_cloud`) es el principal hasta el 9 de noviembre. El respaldo es `groq_oss`: el mismo
modelo gpt-oss-120b en el plan gratuito de Groq. Si el proveedor responde "límite por minuto", el programa espera
y reintenta solo. `--simulado` no usa ninguna API: sirve para probar el flujo, no para sacar conclusiones.
