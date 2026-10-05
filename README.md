# Surface_Recon

Surface_Recon is an experimental reconnaissance orchestrator for authorized security assessment. It characterizes heterogeneous targets, maps required reconnaissance capabilities, reuses compatible capabilities already available in the environment, correlates evidence, and keeps unsupported or unevaluated coverage visible instead of inventing certainty.

> **LAB-001 status:** experimental and under human validation. Passing technical tests does not mean the product or LAB has passed.

## Safety and authorization

Use Surface_Recon only on systems, applications, networks, repositories, files, or other assets you own or are explicitly authorized to assess. Technical capability is not authorization. Surface_Recon is designed for non-destructive reconnaissance and does not make exploitation or destructive action implicit.

## Requirements

- Python 3.13 or newer.
- Git for source-based installation.
- Optional external security tools may extend coverage when Surface_Recon can identify and use them through a verified adapter. Missing tools remain visible as coverage limitations; Surface_Recon does not silently install scanners.

## Install from source

### Windows prerequisite

Surface_Recon requires Python 3.13 or newer. A fresh Windows installation may expose `python`/`python3` Microsoft Store aliases even when Python itself is not installed. Verify the runtime first. `python` is the primary Windows command; `py` is an optional launcher and is not required:

```powershell
python --version
```

If `python` is unavailable, try `python3 --version`. If neither command reports Python 3.13 or newer, install a supported Python release from the official Python distribution, reopen PowerShell, and verify again. Surface_Recon does not silently install or modify system runtimes.

On Windows, the recommended source install is:

```powershell
git clone https://github.com/Luguisaca/surface_recon.git
cd surface_recon
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
python -m surface_recon --help
```

If PowerShell blocks `Activate.ps1`, you do **not** need to weaken the machine's execution policy just to use Surface_Recon. Activation is optional; invoke the environment directly instead:

```powershell
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\python.exe -m surface_recon --help
```

Dependencies are declared by `pyproject.toml` and installed by pip; a separate `requirements.txt` is intentionally not required for normal installation.

### Linux / Unix-like systems

```bash
git clone https://github.com/Luguisaca/surface_recon.git
cd surface_recon
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```



## First run

Assess a target you are authorized to test:

```bash
surface-recon assess https://example.com
```

Run reconnaissance and generate the current evidence/report flow:

```bash
surface-recon recon https://example.com
```

Start the local interactive interface:

```bash
python -m surface_recon serve
```

The UI binds to loopback (`127.0.0.1`) by default and requires explicit authorization before each assessment. `python -m surface_recon` is the portable invocation when the installed console-script directory is not on `PATH`; `surface-recon serve` is equivalent when it is.

Use `surface-recon --help`, `surface-recon assess --help`, `surface-recon recon --help`, or `python -m surface_recon serve --help` for the current CLI contract.

## What to expect

Surface_Recon may combine its owned bounded reconnaissance with compatible providers already installed on the host. It reports executed capabilities, observations, evidence, coverage, and explicit gaps. Availability of a tool does not by itself authorize its use or prove complete coverage.

## Development validation

```bash
python -m pip install -e . pytest
python -m pytest -q
```

Automated tests cover the behaviors represented in this public repository. Controlled validation evidence and HUMAN QA are also required before declaring the LAB complete; technical gates alone are not a product PASS.

## License

Surface_Recon is licensed under the PolyForm Noncommercial License 1.0.0. See `LICENSE` and `NOTICE`.


---

# Surface_Recon — Español

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
