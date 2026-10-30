# Reproducir QA de Edge (sin dependencias npm adicionales)

Requisitos: Node.js con `WebSocket` global, Microsoft Edge/Chromium iniciado en un perfil temporal con `--remote-debugging-port=19223`, y Python con Surface_Recon instalado. **No utilices objetivos externos; la fixture local proporciona autorización controlada.**

En tres terminales, desde la raíz del repositorio (ejemplos PowerShell):

```powershell
python -m http.server 18043 --bind 127.0.0.1 --directory tests/fixtures/browser-ui-site
python -m surface_recon serve --port 18045 --no-open --core-only
& 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe' --headless --disable-gpu --remote-debugging-port=19223 --user-data-dir="$env:TEMP\surface-recon-edge-qa" about:blank
```

Luego:

```powershell
$env:SR_UI='http://127.0.0.1:18045/'
$env:SR_FIXTURE='http://127.0.0.1:18043/'
$env:SR_CDP='http://127.0.0.1:19223'
$env:SR_NOISE='normal' # o low para verificar unlimited+low
$env:SR_QA_DIR="$env:TEMP\surface-recon-browser-evidence"
node tests/browser/edge_cdp_qa.cjs
node tests/browser/accessibility_cdp.cjs
```

Cada ejecución de exportación requiere un directorio nuevo o vacío (`downloads/`), porque el script exige exactamente un archivo de cada formato. Los scripts guardan JSON, capturas y archivos descargados; no sustituyen QA humano ni prueban cumplimiento WCAG completo. Evita usar un servidor anterior desactualizado. Para Linux, modifica la invocación de Edge y rutas según corresponda (soporte no validado).
