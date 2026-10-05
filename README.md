# Surface_Recon

**Español** | [English](README.en.md)


Surface_Recon es un orquestador experimental de reconocimiento para evaluaciones de seguridad autorizadas. Caracteriza objetivos heterogéneos, determina las capacidades de reconocimiento necesarias, reutiliza capacidades compatibles disponibles en el entorno, correlaciona evidencia y mantiene visibles las coberturas no soportadas o no evaluadas.

> **Estado LAB-001:** experimental y en validación humana. Superar pruebas técnicas no significa que el producto o el LAB estén aprobados.

## Seguridad y autorización

Usa Surface_Recon únicamente sobre sistemas, aplicaciones, redes, repositorios, archivos u otros activos propios o para los que tengas autorización explícita. La capacidad técnica no equivale a autorización. El reconocimiento está diseñado para ser no destructivo y no implica explotación automática.

## Requisitos

- Python 3.13 o superior.
- Git para instalar desde el código fuente.
- Herramientas externas de seguridad son opcionales y pueden ampliar cobertura cuando Surface_Recon dispone de una integración verificada. Las ausencias se reportan como limitaciones; no se instalan scanners silenciosamente.

## Instalación desde código fuente

### Windows

Primero verifica Python. En Windows, `python` es el comando principal; `py` es un launcher opcional y **no es requisito**:

```powershell
python --version
```

Si `python` no existe, prueba `python3 --version`. Si ninguno reporta Python 3.13 o superior, instala una versión compatible desde la distribución oficial de Python, vuelve a abrir PowerShell y verifica de nuevo.

```powershell
git clone https://github.com/Luguisaca/surface_recon.git
cd surface_recon
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
python -m pip install .
python -m surface_recon --help
```

Si PowerShell bloquea `Activate.ps1`, no necesitas debilitar la Execution Policy del equipo para usar Surface_Recon. La activación es opcional:

```powershell
.\\.venv\\Scripts\\python.exe -m pip install .
.\\.venv\\Scripts\\python.exe -m surface_recon --help
```

Las dependencias se declaran en `pyproject.toml` y pip las instala automáticamente; no se requiere un `requirements.txt` separado.

### Linux / sistemas tipo Unix

```bash
git clone https://github.com/Luguisaca/surface_recon.git
cd surface_recon
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

## Primer uso

Evaluar un objetivo autorizado:

```bash
surface-recon assess https://example.com
```

Ejecutar reconocimiento y generar el flujo actual de evidencia/reporte:

```bash
surface-recon recon https://example.com
```

Iniciar la interfaz local interactiva:

```bash
python -m surface_recon serve
```

La UI escucha en loopback (`127.0.0.1`) por defecto y exige autorización explícita antes de cada evaluación. `python -m surface_recon` es la invocación portable cuando el script `surface-recon` no está en `PATH`.

## Qué esperar

Surface_Recon puede combinar reconocimiento propio acotado con proveedores compatibles ya instalados. Reporta capacidades ejecutadas, observaciones, evidencia, cobertura y gaps explícitos. Que una herramienta exista no autoriza su uso ni demuestra cobertura completa.

## Validación de desarrollo

```bash
python -m pip install -e . pytest
python -m pytest -q
```

Las pruebas automáticas cubren los comportamientos representados en el repositorio público. También se exige evidencia controlada y HUMAN QA antes de declarar completo el LAB.

## Licencia

Surface_Recon usa PolyForm Noncommercial License 1.0.0. Consulta `LICENSE` y `NOTICE`.
