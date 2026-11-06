"""Las herramientas de revisión, sin IA: leer el código, Bandit, Semgrep, pip-audit, PyPI y las pruebas.

El servidor MCP (servidor_mcp.py) las publica para el modelo, y los controles (controles.py) las usan
directamente para verificar lo que dice el modelo. Trabajan sobre la carpeta de la aplicación indicada en
la variable ANDINA_APP_DIR (por defecto, app_andina/); los ataques la cambian por una copia modificada.
"""
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
REGLAS = BASE / "reglas_semgrep" / "andina.yml"


def carpeta_app() -> Path:
    return Path(os.getenv("ANDINA_APP_DIR", BASE / "app_andina")).resolve()


def ruta_segura(archivo: str) -> Path:
    """Solo permite archivos dentro de la carpeta de la aplicación (evita ../../ y rutas absolutas)."""
    raiz = carpeta_app()
    p = (raiz / archivo).resolve()
    if raiz not in p.parents and p != raiz:
        raise ValueError(f"Ruta fuera de la aplicación: {archivo}")
    if not p.is_file():
        raise ValueError(f"No existe el archivo: {archivo}")
    return p


def listar_archivos() -> list[str]:
    raiz = carpeta_app()
    return sorted(str(p.relative_to(raiz)) for p in raiz.rglob("*") if p.is_file() and "__pycache__" not in p.parts)


def _correr(cmd: list[str], timeout: int, **kw) -> subprocess.CompletedProcess:
    """Ejecuta un programa externo desde el servidor MCP.

    stdin=DEVNULL es clave: el servidor habla con el cliente por su stdin (transporte stdio). Si el programa hijo
    hereda ese stdin, en Windows se queda esperando y la herramienta no responde nunca. Además: UTF-8 y tiempo máximo.
    """
    env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8", **kw.pop("env", {})}
    return subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=timeout, env=env, **kw)


def leer_codigo(archivo: str = "app.py", desde: int = 1, hasta: int = 0) -> str:
    lineas = ruta_segura(archivo).read_text(encoding="utf-8").splitlines()
    hasta = len(lineas) if hasta <= 0 else min(hasta, len(lineas))
    return "\n".join(f"{i:>4}  {lineas[i - 1]}" for i in range(max(1, desde), hasta + 1))


def bandit(carpeta: Path | None = None) -> list[dict]:
    try:
        r = _correr([sys.executable, "-m", "bandit", "-r", str(carpeta or carpeta_app()), "-f", "json", "-q"], timeout=120)
    except subprocess.TimeoutExpired:
        raise RuntimeError("Bandit no terminó en 120 segundos")
    try:
        datos = json.loads(r.stdout)["results"]
    except (json.JSONDecodeError, KeyError):
        raise RuntimeError(f"Bandit no entregó resultados: {r.stderr.strip()[:200]}")
    return [{"herramienta": "bandit", "archivo": Path(x["filename"]).name, "linea": x["line_number"], "regla": x["test_id"],
             "severidad": x["issue_severity"], "cwe": f"CWE-{x['issue_cwe']['id']}", "mensaje": x["issue_text"]} for x in datos]


def semgrep() -> list[dict] | None:
    exe = shutil.which("semgrep")
    if not exe:
        return None
    try:
        r = _correr([exe, "--config", str(REGLAS), "--json", "--quiet", "--metrics=off", "--disable-version-check", str(carpeta_app())],
                    timeout=300, env={"SEMGREP_ENABLE_VERSION_CHECK": "0"})
    except subprocess.TimeoutExpired:
        return None
    try:
        datos = json.loads(r.stdout)["results"]
    except (json.JSONDecodeError, KeyError):
        return None
    out = []
    for x in datos:
        cwe = x["extra"].get("metadata", {}).get("cwe", "")
        cwe = cwe[0] if isinstance(cwe, list) else cwe
        num = re.sub(r"\D", "", str(cwe).split(":")[0])
        out.append({"herramienta": "semgrep", "archivo": Path(x["path"]).name, "linea": x["start"]["line"], "regla": x["check_id"].split(".")[-1],
                    "severidad": x["extra"]["severity"], "cwe": f"CWE-{num}" if num else "", "mensaje": x["extra"]["message"][:200]})
    return out


def pip_audit() -> tuple[list[dict], str]:
    """Vulnerabilidades de requirements.txt. Si no hay red, usa la respuesta guardada en data/pip_audit_cache.json."""
    req = carpeta_app() / "requirements.txt"
    exe = shutil.which("pip-audit")
    datos, origen = None, "pip-audit en vivo"
    if exe:
        try:
            r = _correr([exe, "-r", str(req), "--no-deps", "--disable-pip", "-f", "json", "--progress-spinner", "off"], timeout=240)
            datos = json.loads(r.stdout)
        except (json.JSONDecodeError, subprocess.TimeoutExpired):
            datos = None
    if datos is None:
        datos, origen = json.loads((DATA / "pip_audit_cache.json").read_text(encoding="utf-8")), "respuesta guardada (sin red)"
    filas = []
    for dep in datos.get("dependencies", []):
        if dep.get("skip_reason"):
            filas.append({"paquete": dep["name"], "version": dep.get("version") or "", "estado": "No se pudo auditar", "detalle": dep["skip_reason"]})
            continue
        ids = sorted({next((a for a in v.get("aliases", []) if a.startswith("CVE-")), v["id"]) for v in dep.get("vulns", [])})
        filas.append({"paquete": dep["name"], "version": dep["version"], "estado": "Vulnerable" if ids else "Sin vulnerabilidades conocidas",
                      "detalle": ", ".join(ids)})
    return filas, origen


def existe_en_pypi(nombre: str) -> tuple[bool | None, str]:
    """¿Existe el paquete en PyPI? Devuelve (respuesta, origen). Sin red usa data/pypi_cache.json."""
    nombre = re.split(r"[<>=!~\[ ]", nombre.strip())[0].lower()
    try:
        import httpx
        r = httpx.get(f"https://pypi.org/pypi/{nombre}/json", timeout=10)
        if r.status_code in (200, 404):
            return r.status_code == 200, "PyPI en vivo"
    except Exception:
        pass
    cache = json.loads((DATA / "pypi_cache.json").read_text(encoding="utf-8"))["paquetes"]
    if nombre in cache:
        return cache[nombre] == 200, "respuesta guardada (sin red)"
    return None, "sin red y sin respuesta guardada"


def pruebas(carpeta: Path) -> dict:
    """Corre las pruebas funcionales (no romper) y de seguridad (corregir) sobre la carpeta indicada."""
    out = {}
    for nombre, archivo in (("funcionales", "test_app.py"), ("seguridad", "test_seguridad.py")):
        try:
            r = _correr([sys.executable, "-m", "pytest", "-q", "--no-header", "-p", "no:cacheprovider", str(BASE / "tests" / archivo)],
                        timeout=180, env={"APP_DIR": str(carpeta)}, cwd=BASE)
        except subprocess.TimeoutExpired:
            out[nombre] = {"pasan": 0, "total": 0}
            continue
        ok = int(m.group(1)) if (m := re.search(r"(\d+) passed", r.stdout)) else 0
        mal = sum(int(x) for x in re.findall(r"(\d+) (?:failed|error)", r.stdout))
        out[nombre] = {"pasan": ok, "total": ok + mal}
    return out


CORREGIDA = BASE / "salidas" / "remediacion" / "app_andina"


def carpeta_version(version: str) -> Path:
    """'original' = la aplicación revisada · 'corregida' = la copia que escribe la remediación."""
    if version == "original":
        return carpeta_app()
    if version == "corregida":
        if not (CORREGIDA / "app.py").exists():
            raise ValueError("Todavía no hay versión corregida: guarden una con guardar_correccion.")
        return CORREGIDA
    raise ValueError("version debe ser 'original' o 'corregida'")


def _borrar_copia(carpeta: Path) -> None:
    """Borra la copia aunque tenga atributo de solo lectura: copytree lo hereda del original y, en Windows, rmtree falla (WinError 5)."""
    for raiz, _, archivos in os.walk(carpeta):
        for ruta in [raiz, *(os.path.join(raiz, a) for a in archivos)]:
            os.chmod(ruta, os.stat(ruta).st_mode | stat.S_IWRITE)
    shutil.rmtree(carpeta)


def guardar_correccion(codigo: str) -> str:
    """Escribe app.py corregido en una COPIA de la aplicación (salidas/remediacion/app_andina). Nunca toca el original."""
    if "from flask import" not in codigo or "app = Flask" not in codigo:
        raise ValueError("El código no parece ser el app.py completo de la API.")
    if CORREGIDA.exists():
        _borrar_copia(CORREGIDA)
    shutil.copytree(carpeta_app(), CORREGIDA, ignore=shutil.ignore_patterns("__pycache__"))
    (CORREGIDA / "app.py").write_text(codigo, encoding="utf-8")
    return f"app.py corregido guardado en la copia ({len(codigo.splitlines())} líneas)"


def pruebas_detalle(carpeta: Path) -> dict:
    """Corre las pruebas funcionales y de seguridad y devuelve el resultado de cada una, con el motivo si falla."""
    out = {}
    for tipo, archivo in (("funcional", "test_app.py"), ("seguridad", "test_seguridad.py")):
        try:
            r = _correr([sys.executable, "-m", "pytest", "-q", "-rA", "--no-header", "-p", "no:cacheprovider", "--tb=line",
                         str(BASE / "tests" / archivo)], timeout=180, env={"APP_DIR": str(carpeta), "COLUMNS": "250"}, cwd=BASE)
            salida = r.stdout
        except subprocess.TimeoutExpired:
            salida = ""
        for m in re.finditer(r"^(PASSED|FAILED|ERROR) \S*::(\w+)(?: - (.*))?$", salida, flags=re.M):
            out[m.group(2)] = {"tipo": tipo, "ok": m.group(1) == "PASSED", "motivo": (m.group(3) or "")[:200]}
    return out
