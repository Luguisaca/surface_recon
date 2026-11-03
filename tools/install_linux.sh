#!/usr/bin/env bash
# Instalacion guiada local; no instala paquetes del sistema ni modifica Python global.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
echo "Surface_Recon | Instalacion guiada Linux"
if [[ -n "${SURFACE_RECON_PYTHON:-}" ]]; then
  candidate="$SURFACE_RECON_PYTHON"
elif command -v python3.13 >/dev/null 2>&1; then
  candidate="python3.13"
else
  candidate="python3"
fi
if ! command -v "$candidate" >/dev/null 2>&1; then
  echo "ERROR: Python no encontrado. Instala Python 3.13 o superior y vuelve a ejecutar." >&2
  exit 10
fi
if ! "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3,13) else 1)' ; then
  echo "ERROR: Surface_Recon requiere Python >=3.13; encontrado: $("$candidate" --version 2>&1)." >&2
  echo "No modifiques el Python del sistema. Instala una version compatible en paralelo." >&2
  exit 11
fi
if ! "$candidate" -m venv --help >/dev/null 2>&1; then
  echo "ERROR: falta soporte venv. Instala el paquete venv correspondiente a tu version Python." >&2
  exit 12
fi
if [[ -e .venv ]]; then
  if [[ ! -x .venv/bin/python ]]; then
    echo "ERROR: .venv existe pero esta incompleto. Renombralo o retiralo tras revisar su contenido." >&2
    exit 13
  fi
  if ! .venv/bin/python -c 'import sys; sys.exit(0 if sys.version_info >= (3,13) else 1)' ; then
    echo "ERROR: .venv existente usa Python incompatible. Renombra o revisa .venv antes de continuar." >&2
    exit 15
  fi
fi
"$candidate" -m venv .venv || { echo "ERROR: no fue posible crear .venv; comprueba ensurepip/venv." >&2; exit 14; }
.venv/bin/python -m pip install .
echo
echo "Instalacion completa. Para iniciar la interfaz local:"
echo "  .venv/bin/python -m surface_recon serve"
echo "Abre en tu navegador la direccion local que muestre el servicio."
echo "Para detenerlo: Ctrl+C. Para ayuda: .venv/bin/python -m surface_recon --help"
echo "Usa solo objetivos propios o expresamente autorizados."
