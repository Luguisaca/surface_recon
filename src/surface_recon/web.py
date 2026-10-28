"""Loopback-only interactive Surface_Recon UI."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import webbrowser

from .assessment import assess_targets
from .controls import ReconControls
from .redaction import minimize
from .reporting import csv_export, export_payload, human_error, report_body
from .results import _jsonable, _surface_data

_HTML = r"""<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Surface_Recon</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;background:#0d1117;color:#e6edf3;margin:0}main{max-width:1180px;margin:auto;padding:24px}.panel,article{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin:12px 0}.row{display:flex;gap:8px;flex-wrap:wrap}input[type=text]{flex:1;min-width:260px}input,select,button{padding:9px}button{cursor:pointer}.muted{color:#adb9c7}.warn{border-left:4px solid #f0883e}table{width:100%;border-collapse:collapse;table-layout:fixed}th,td{text-align:left;vertical-align:top;padding:8px;border-bottom:1px solid #30363d;overflow-wrap:anywhere}code{color:#79c0ff;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere}details{margin:10px 0}</style></head>
<body><main><header><small>IA DIRECTOR · LAB-001</small><h1>Surface_Recon</h1><p>Reconocimiento autorizado, progresivo y orientado a evidencia.</p></header>
<section class="panel"><label>Objetivo autorizado</label><div class="row"><input id="target" type="text" placeholder="URL, host, red, archivo, directorio o repositorio"><button id="run">Reconocer</button></div>
<div class="row"><label>Perfil <select id="profile"><option value="auto">Auto</option><option value="passive">Pasivo · solo evidencia local</option><option value="active">Activo · core acotado</option><option value="balanced">Equilibrado · providers pertinentes</option><option value="deep">Profundo · mayor presupuesto web</option></select></label>
<label>Ruido <select id="noise"><option value="normal">Normal</option><option value="low">Bajo</option></select></label>
<label>Solo proveedores <input id="include" type="text" placeholder="nmap,nuclei…"></label><label>Excluir <input id="exclude" type="text" placeholder="nmap,nuclei…"></label></div>
<label><input id="authorized" type="checkbox"> Confirmo que estoy autorizado a evaluar este objetivo.</label>
<p id="profile-help" class="muted">Auto elige capacidades según el objetivo. Pasivo solo revisa evidencia local; no hace ingeniería inversa ni pruebas de red. Para ampliar cobertura, selecciona otro perfil y revisa los permisos y herramientas disponibles.</p><details><summary>Opciones avanzadas: herramientas y proveedores</summary><p>Los campos Solo proveedores y Excluir son filtros opcionales, no instalan herramientas. La tabla del informe distingue detectado, seleccionado y ejecutado.</p></details><p class="muted">Auto decide por cobertura. Los providers son overrides avanzados; detectado no significa ejecutado. 0 hallazgos no significa seguro.</p><p id="status" role="status" aria-live="polite"></p></section>
<section id="result" hidden><article class="warn"><h2>Qué falta comprobar</h2><p>La cobertura no evaluada y las limitaciones aparecen dentro del informe. No se convierten en ausencia de riesgo.</p></article><article><h2>Cómo continuar</h2><ol><li>Revisa la cobertura no evaluada: no equivale a ausencia de riesgos.</li><li>Si elegiste Pasivo, prueba Auto solo cuando tengas autorización para ampliar el reconocimiento.</li><li>Consulta la tabla de proveedores: detectado no significa ejecutado; instalar herramientas es una decisión separada.</li><li>Para ingeniería inversa de software se necesita un análisis específico: este reconocimiento de archivos no lo demuestra.</li></ol><p>Conserva el informe y las evidencias para planificar una evaluación posterior dentro del alcance autorizado.</p></article><div id="human"></div><nav id="exports" class="row" aria-label="Descargar evidencias" hidden><button id="save-html" type="button">Descargar informe HTML</button><button id="save-json" type="button">Exportar JSON</button><button id="save-csv" type="button">Exportar CSV</button></nav></section>
<script>
const $=x=>document.getElementById(x), list=x=>$(x).value.split(',').map(v=>v.trim()).filter(Boolean);
let lastReport=null;
function downloadReport(content,type,extension){if(!lastReport)return;const blob=new Blob([content],{type});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='surface-recon-'+lastReport.run_id+'.'+extension;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000)}
$('save-html').onclick=()=>downloadReport('<!doctype html><html lang="es"><head><meta charset="utf-8"><title>Surface_Recon</title></head><body>'+lastReport.html+'</body></html>','text/html;charset=utf-8','html');
$('save-json').onclick=()=>downloadReport(JSON.stringify(lastReport.export,null,2),'application/json;charset=utf-8','json');
$('save-csv').onclick=()=>downloadReport(lastReport.csv,'text/csv;charset=utf-8','csv');
$('run').onclick=async()=>{const target=$('target').value.trim();$('result').hidden=true;$('exports').hidden=true;lastReport=null;if(!target){$('status').textContent='Falta el objetivo: escribe una ruta local, URL o host autorizado.';$('target').focus();return}if(!$('authorized').checked){$('status').textContent='Falta la autorización: marca la casilla de confirmación antes de reconocer.';$('authorized').focus();return}
$('run').disabled=true;$('status').textContent='Reconociendo…';try{const body={target,authorized:true,profile:$('profile').value,noise:$('noise').value,include:list('include'),exclude:list('exclude')};
const r=await fetch('/api/assess',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const d=await r.json();if(!r.ok)throw new Error(d.error||'Falló la evaluación');
$('human').innerHTML=d.html;lastReport=d;$('exports').hidden=false;$('result').hidden=false;$('status').textContent='Reconocimiento completado. Revisa cobertura, evidencia y siguientes pasos.'}catch(e){$('status').textContent=e.message}finally{$('run').disabled=false}};
</script></main></body></html>"""

def inspect_authorized(target: str, *, authorized: bool, use_extensions: bool = True,
                       profile: str = "auto", noise: str = "normal",
                       include=(), exclude=()) -> dict:
    target = str(target).strip()
    if not target or authorized is not True:
        raise ValueError("Target and explicit authorization are required.")
    controls = ReconControls(profile, noise, tuple(include), tuple(exclude))
    assessment = assess_targets([target], use_extensions=use_extensions, controls=controls)
    rows = minimize(_jsonable(_surface_data(assessment)))
    supported = sum(1 for finding in assessment.findings if getattr(finding.status, "value", finding.status) == "supported")
    payload = export_payload(assessment)
    return {"status": assessment.status.value, "supported_findings": supported, "rows": rows,
            "html": report_body(payload), "export": payload, "csv": csv_export(payload), "run_id": payload["run_id"]}

def _handler(use_extensions: bool):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path not in {"/", "/index.html"}:
                self.send_error(404); return
            raw = _HTML.encode("utf-8")
            self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",str(len(raw))); self.end_headers(); self.wfile.write(raw)
        def do_POST(self):
            if self.path != "/api/assess":
                self.send_error(404); return
            try:
                length = int(self.headers.get("Content-Length","0"))
                if length < 1 or length > 16384:
                    raise ValueError("Solicitud inválida o demasiado grande.")
                body = json.loads(self.rfile.read(length))
                payload = inspect_authorized(body.get("target",""), authorized=body.get("authorized") is True,
                    use_extensions=use_extensions, profile=body.get("profile","auto"), noise=body.get("noise","normal"),
                    include=body.get("include") or (), exclude=body.get("exclude") or ())
                raw = json.dumps(payload, ensure_ascii=False).encode("utf-8"); status=200
            except Exception as exc:
                raw = json.dumps({"error": human_error(exc)}, ensure_ascii=False).encode("utf-8"); status=400
            self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8"); self.send_header("Content-Length",str(len(raw))); self.end_headers(); self.wfile.write(raw)
        def log_message(self, *_args):
            return
    return Handler

def serve_local(*, port: int = 8041, open_browser: bool = True, use_extensions: bool = True) -> None:
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    server = ThreadingHTTPServer(("127.0.0.1", port), _handler(use_extensions))
    url = f"http://127.0.0.1:{port}/"
    print(f"Surface_Recon UI: {url}", flush=True)
    print("Loopback only; every assessment requires explicit authorization.", flush=True)
    if open_browser:
        threading.Timer(0.2, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
