# Surface_Recon

Surface_Recon is an experimental reconnaissance orchestrator for authorized security assessment. It characterizes heterogeneous targets, maps required reconnaissance capabilities, reuses compatible capabilities already available in the environment, correlates evidence, and keeps unsupported or unevaluated coverage visible instead of inventing certainty.

> **Release status:** experimental. Automated checks do not establish comprehensive coverage, security certification or support for every target.

## Safety and authorization

Use Surface_Recon only on systems, applications, networks, repositories, files, or other assets you own or are explicitly authorized to assess. Technical capability is not authorization. Surface_Recon is designed for non-destructive reconnaissance and does not make exploitation or destructive action implicit.

## Requirements

- Python 3.13 or newer.
- Git for source-based installation.
- Optional external security tools may extend coverage when Surface_Recon can identify and use them through a verified adapter. Missing tools remain visible as coverage limitations; Surface_Recon does not silently install scanners.

## Install from source

```bash
git clone https://github.com/Luguisaca/surface_recon.git
cd surface_recon
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

Windows activation uses `.venv\\Scripts\\activate` instead.

## First run

Assess a target you are authorized to test. The explicit `--authorized` attestation is required before active CLI reconnaissance:

```bash
surface-recon assess --authorized https://example.com
```

Run reconnaissance and generate the current evidence/report flow:

```bash
surface-recon recon --authorized https://example.com
```

Use `surface-recon --help`, `surface-recon assess --help`, or `surface-recon recon --help` for the current CLI contract.

## Control de reconocimiento

El modo normal sigue siendo autónomo. `--mode auto` selecciona capacidades por evidencia y cobertura. También puedes usar `passive` (solo evidencia local), `active` (core acotado sin providers externos), `balanced` o `deep`. `--intensity low` reduce ruido y desactiva providers; `--include-provider` y `--exclude-provider` son overrides avanzados sobre adapters verificados, no una obligación de elegir herramientas manualmente.

`recon` genera un informe humano y exports JSON/CSV reutilizables. Para profundizar una corrida sin copiar hosts manualmente, usa `--continue-from <export.json> --authorized`; la continuación conserva únicamente el alcance originalmente autorizado y no promueve referencias descubiertas a nuevo scope.

La interfaz `serve` ofrece los mismos perfiles básicos y presenta tablas humanas; el JSON queda como evidencia secundaria. Una ruta/hipótesis descartada por 404/410 no se presenta como superficie activa.

## Presupuestos y límites HTTP vigentes

Para objetivos URL: `auto` y `balanced` permiten hasta **300 solicitudes / 300 s**; `deep`, **1.000 / 600 s**; `--intensity low`, **60 / 120 s**, con ritmo reducido y sin proveedores externos. El modo `--mode unlimited` o su opción web **elimina solo el límite de cantidad de solicitudes**: conserva plazo de **3.600 s**, autorización, origen permitido, pausas y cancelación. Con `unlimited` + intensidad baja se mantiene la cantidad sin tope y el ritmo conservador.

El motor puede finalizar antes si agota las rutas observadas. Ante HTTP 429/503 respeta `Retry-After` en los casos probados y detiene ante saturación prolongada; no sigue redirecciones fuera del origen. **No** garantiza descubrir rutas que no estén referenciadas, ni ajusta automáticamente el techo máximo al tamaño del sitio. Pruebas de Edge y exportaciones reales documentadas en `tests/browser/QA-2026-10-30.md`; QA humano favorable de cinco flujos (2026-10-30), **sin aprobación de publicación**.

## What to expect

Surface_Recon may combine its owned bounded reconnaissance with compatible providers already installed on the host. It reports executed capabilities, observations, evidence, coverage, and explicit gaps. Availability of a tool does not by itself authorize its use or prove complete coverage.

## Development validation

```bash
python -m pip install -e . pytest
python -m pytest -q
```

Technical checks and controlled evidence are maintained under `tests/`, `benchmarks/` and `specs/`. Validate capabilities against your own authorized scope; do not infer exhaustive discovery or reverse engineering from a completed run.

## License

Surface_Recon is licensed under the PolyForm Noncommercial License 1.0.0. See `LICENSE` and `NOTICE`.

### Autocompletado de CLI

Surface_Recon instala soporte de completion mediante `argcomplete`. Se activa una vez por shell:

```bash
# Bash / Kali / Parrot
eval "$(register-python-argcomplete surface-recon)"
```

```powershell
# PowerShell / Windows (sesi?n actual)
register-python-argcomplete --shell powershell surface-recon | Out-String | Invoke-Expression
```

Despu?s, `surface-recon recon --<TAB>` completa las opciones disponibles. La activaci?n persistente depende del perfil/configuraci?n del shell y no se modifica autom?ticamente.

### Ritmo y providers

`--mode passive` es la opci?n de **cero red**: para objetivos de red falla cerrado en vez de resolver DNS o enviar probes. `--intensity low --pace-ms N` reduce el ritmo del core y desactiva providers externos, pero **no garantiza invisibilidad ni evasi?n de detecci?n**. `--provider-timeout SEGUNDOS` permite ampliar o reducir el tiempo m?ximo de un provider sin eliminar los l?mites existentes.
