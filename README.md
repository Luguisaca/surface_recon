# Surface_Recon

**Español** | [English](README.en.md)

Surface_Recon es un orquestador experimental de reconocimiento para evaluaciones de seguridad autorizadas. Caracteriza objetivos diversos, identifica capacidades necesarias, reutiliza herramientas compatibles disponibles y correlaciona observaciones con evidencias. Declara la cobertura no evaluada y las limitaciones en lugar de inventar hallazgos.

> **Estado:** experimental. Las funcionalidades pueden evolucionar; los resultados no constituyen una evaluación de seguridad exhaustiva.

## Seguridad y autorización

Úsalo exclusivamente sobre sistemas, aplicaciones, redes, repositorios, archivos y otros activos propios o expresamente autorizados. Disponer de una capacidad técnica no concede autorización. El reconocimiento está diseñado para ser no destructivo: no autoriza explotación ni acciones destructivas.

## Requisitos

- Python **3.13 o superior**. Verifica la versión antes de instalar.
- Git para instalar desde el repositorio.
- Herramientas externas opcionales: solo se utilizan mediante adaptadores pertinentes y comprobados. Su ausencia se informa como límite de cobertura; no se instalan escáneres silenciosamente.

## Instalación desde el código fuente

Clona el código fuente desde el repositorio oficial de Surface_Recon:

```bash
git clone https://github.com/Luguisaca/surface_recon.git
cd surface_recon
```

### Linux, Ubuntu, Debian y WSL

Ubuntu 24.04 incluye Python 3.12 de forma predeterminada. Instalar el paquete `python3.12-venv` **no** satisface el requisito de Python 3.13+. Instala una versión compatible en paralelo; no modifiques el Python del sistema ni utilices `sudo pip`.

```bash
cd RUTA_AL_CODIGO_FUENTE_VERIFICADO
bash tools/install_linux.sh
```

El instalador valida Python, crea un entorno virtual local, instala el proyecto y muestra los comandos de inicio. Si tienes varios intérpretes, especifica el compatible sin modificar el global:

```bash
SURFACE_RECON_PYTHON=python3.13 bash tools/install_linux.sh
```

También puedes realizar la instalación manual:

```bash
python3.13 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/python -m surface_recon --help
```

Si falta `venv` o `ensurepip`, instala el paquete que corresponda **a esa misma versión de Python**. No elimines un entorno `.venv` previo sin inspeccionarlo.

### Windows (PowerShell)

Verifica Python 3.13+ con `python --version` (o `python3 --version` si corresponde). En Windows pueden existir alias de Microsoft Store sin una instalación funcional; reabre PowerShell después de instalar una versión compatible.

```powershell
cd RUTA_AL_CODIGO_FUENTE_VERIFICADO
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\python.exe -m surface_recon --help
```

No es necesario activar el entorno virtual ni reducir la política de ejecución de PowerShell. Las dependencias se declaran en `pyproject.toml`.

## Primer uso

Para abrir la interfaz local:

```bash
.venv/bin/python -m surface_recon serve
```

En Windows usa `.\.venv\Scripts\python.exe -m surface_recon serve`. La interfaz escucha en `127.0.0.1` por defecto; abre la dirección que muestre y detén el servicio con `Ctrl+C`.

Para obtener una evaluación técnica o generar un informe visual, proporciona **únicamente objetivos autorizados**:

```bash
surface-recon assess --authorized https://example.com
surface-recon recon --authorized https://example.com
```

Los dominios son ejemplos de sintaxis, no una autorización de prueba. Cuando el ejecutable no esté en `PATH`, usa `python -m surface_recon` desde el entorno virtual. Consulta `--help` y la ayuda de cada subcomando.

## Modos y controles de reconocimiento

El modo `--mode auto` selecciona capacidades según cobertura y evidencia. También existen `passive` (sin tráfico de red), `active`, `balanced`, `deep` y `unlimited`. La intensidad `low` reduce ruido y desactiva proveedores externos. `--include-provider` y `--exclude-provider` son controles avanzados, no pasos obligatorios.

`recon` produce un informe HTML y exportaciones JSON/CSV. Puedes continuar un informe previo con `--continue-from ARCHIVO.json --authorized`; las referencias descubiertas no se convierten automáticamente en objetivos autorizados.

## Presupuestos HTTP y límites

| Perfil | Solicitudes | Plazo |
| --- | ---: | ---: |
| `auto` | 300 iniciales; puede ampliar hasta 1.200 | 300 s |
| `balanced` | 300 | 300 s |
| `deep` | 1.000 | 600 s |
| Intensidad `low` | 60 | 120 s |
| `unlimited` | Sin tope de cantidad | 3.600 s |

`auto` amplía de 100 en 100 solo cuando al menos 25 respuestas útiles del mismo origen justifican candidatos pendientes; no aumenta el plazo. `unlimited` elimina **únicamente** el límite numérico: conserva autorización, alcance de origen, pausas, cancelación y límite temporal. El motor puede terminar antes cuando se agota la frontera descubierta.

HTTP 429/503 activa tratamiento acotado de `Retry-After`; un bloqueo prolongado termina con cobertura parcial. No se siguen redirecciones a otros orígenes. HTTP 404/429/503 no justifica ampliar el presupuesto. No se garantiza descubrir rutas no enlazadas ni cobertura exhaustiva.

## Informes, cobertura y limitaciones

Surface_Recon informa capacidades ejecutadas, observaciones, evidencias, cobertura y brechas pendientes. La disponibilidad de una herramienta no demuestra que se haya ejecutado ni que el objetivo esté cubierto. La interfaz muestra resultados interpretables; JSON/CSV son exportaciones reutilizables, no sustituyen la evaluación humana.

## Comprobación de instalación

Con Python 3.13 o superior y `uv` instalado, comprueba las opciones del programa:

```bash
uv sync --locked
uv run --locked python -m surface_recon --help
uv run --locked python -m surface_recon serve --help
```

Estos comandos no ejecutan reconocimiento contra ningún objetivo.

## Autocompletado de comandos

```bash
# Bash, Kali y Parrot
eval "$(register-python-argcomplete surface-recon)"
```

```powershell
# PowerShell (sesión actual)
register-python-argcomplete --shell powershell surface-recon | Out-String | Invoke-Expression
```

La activación persistente depende del perfil de la terminal y no se modifica automáticamente. `--intensity low --pace-ms N` reduce el ritmo, pero **no** promete invisibilidad o evasión de detección; `--provider-timeout` ajusta el tiempo por proveedor sin eliminar otros límites.

## Licencia

Surface_Recon se distribuye bajo **PolyForm Noncommercial 1.0.0**. El uso comercial por terceros requiere una autorización escrita independiente del titular de derechos. La licencia del producto no sustituye las licencias propias de sus dependencias. Consulta `LICENSE` y `NOTICE` (inventario de terceros). Para reportes privados, consulta [la política de seguridad](SECURITY.md).
