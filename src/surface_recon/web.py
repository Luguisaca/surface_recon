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
<style>
:root{color-scheme:dark;--bg:#080f1c;--surface:#101c2e;--surface2:#14243a;--line:#2a3b54;--text:#edf5ff;--muted:#b2c4d8;--accent:#66ddc8;--blue:#85baff;--amber:#ffc17a}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:radial-gradient(ellipse at 85% 0%,#163453 0%,transparent 44%),var(--bg);color:var(--text);font:15px/1.55 system-ui,Segoe UI,Arial,sans-serif}main{max-width:1360px;margin:auto;padding:32px 36px 80px}.mast{display:flex;align-items:center;justify-content:space-between;gap:20px;border-bottom:1px solid var(--line);padding-bottom:24px;margin-bottom:30px}.brand{font-size:12px;font-weight:800;letter-spacing:.16em;color:var(--accent)}.tag{border:1px solid #446c74;color:#baf5e8;padding:6px 12px;border-radius:30px;font-size:12px}.hero{display:grid;grid-template-columns:minmax(0,1fr) 320px;gap:24px;align-items:stretch;margin-bottom:26px}.hero h1{font-size:clamp(32px,4.2vw,56px);line-height:1.06;letter-spacing:-.04em;margin:12px 0 18px}.hero p{font-size:16px;color:var(--muted);max-width:670px}.hero strong{color:var(--text)}.hero-aside{background:linear-gradient(145deg,#1b344c,#102032);border:1px solid #33556a;border-radius:18px;padding:25px}.hero-aside b{font-size:14px}.hero-aside ol{padding-left:20px;color:#c9dbe9}.hero-aside li{margin:10px 0}.panel,article{background:linear-gradient(150deg,#142238,#0e1a2b);border:1px solid var(--line);border-radius:16px;padding:24px;margin:16px 0;box-shadow:0 10px 30px #0002}.panel h2{margin:0 0 6px;font-size:21px}.muted,.helper{color:var(--muted)}.helper{font-size:13px}.row{display:flex;gap:14px;flex-wrap:wrap;align-items:end}.field{display:flex;flex-direction:column;gap:8px;flex:1;min-width:200px}label{font-weight:600;font-size:13px}input[type=text],select{width:100%;background:#0b1727;border:1px solid #456079;color:var(--text);border-radius:9px;padding:13px 14px;font:inherit;min-height:48px}input[type=text]:focus,select:focus,button:focus-visible,summary:focus-visible{outline:3px solid var(--accent);outline-offset:2px}input::placeholder{color:#91a6bc}button{background:var(--accent);color:#062521;border:0;border-radius:9px;padding:13px 21px;font-weight:800;font-size:14px;cursor:pointer;min-height:48px}button:hover{filter:brightness(1.08)}button:disabled{opacity:.6;cursor:wait}.secondary{background:#203b56;color:#dbefff;border:1px solid #41617a}.auth{display:flex;align-items:flex-start;gap:12px;padding:16px;background:#0c1c2b;border:1px solid #36536a;border-radius:10px;margin:18px 0}.auth input{width:18px;height:18px;accent-color:var(--accent);margin-top:2px}.auth label{font-size:14px}.section-heading{display:flex;align-items:center;justify-content:space-between;gap:16px}.section-heading span{font-size:12px;color:var(--accent);letter-spacing:.1em;font-weight:800}.warn{border-left:4px solid var(--amber)}.summary-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin:20px 0}.metric{background:#0e2234;border:1px solid #35526b;border-radius:12px;padding:20px}.metric b{display:block;font-size:30px;color:var(--accent)}.metric span{color:var(--muted);font-size:13px}#result{margin-top:28px}#status{padding:10px 0;font-weight:600;color:var(--accent);min-height:26px}#human{overflow-x:auto}#human table{width:100%;border-collapse:collapse}#human th,#human td{padding:11px;text-align:left;border-bottom:1px solid #31445d;overflow-wrap:anywhere}#human pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:360px;overflow:auto}#human details{margin:12px 0}details{margin:16px 0}summary{cursor:pointer;color:var(--blue);font-weight:700}code{color:var(--blue);overflow-wrap:anywhere}nav{margin-top:18px}nav button{background:#1b3b55;color:#e8f7ff;border:1px solid #42617b}.footer{color:#92a9c0;font-size:12px;margin-top:32px;border-top:1px solid var(--line);padding-top:18px}@media(max-width:850px){main{padding:20px 16px}.hero{grid-template-columns:1fr}.summary-grid{grid-template-columns:1fr}.mast{flex-wrap:wrap}.panel,article{padding:18px}}@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
</style></head>
<body><main><header class="mast"><div><div class="brand">LUGUISACA / SECURITY ENGINEERING</div><div class="muted">Reconocimiento de superficies</div></div><span class="tag">MVP experimental · evaluación autorizada</span></header><section class="hero"><div><div class="brand">SURFACE INTELLIGENCE</div><h1>Surface_Recon<span style="color:var(--accent)">.</span></h1><p>Descubre y documenta superficies técnicas dentro de un alcance autorizado. <strong>Resultados verificables, límites explícitos y evidencias reutilizables.</strong></p></div><aside class="hero-aside"><b>Flujo de investigación</b><ol><li>Define el objetivo y el alcance</li><li>Ejecuta el perfil autorizado</li><li>Examina hallazgos y cobertura</li><li>Exporta el informe y las evidencias</li></ol></aside></section>
<section class="panel" aria-labelledby="scope-heading"><div class="section-heading"><h2 id="scope-heading">Configurar reconocimiento</h2><span>01 / ALCANCE</span></div><p class="helper">Introduce un dominio, URL, host o ruta local. El reconocimiento no amplía automáticamente la autorización a otros objetivos.</p><div class="row"><div class="field"><label for="target">Objetivo autorizado</label><input id="target" type="text" autocomplete="off" placeholder="https://ejemplo.com o C:\\ruta\\carpeta"></div><button id="run" type="button">Iniciar reconocimiento</button></div>
<div class="row" style="margin-top:18px"><div class="field"><label for="profile">Perfil de análisis</label><select id="profile"><option value="auto">Auto (adaptativo, máximo 1.200)</option><option value="passive">Pasivo · solo evidencia local</option><option value="active">Activo · core acotado</option><option value="balanced">Equilibrado · providers pertinentes</option><option value="deep">Profundo · mayor presupuesto web</option><option value="unlimited">Sin límite de solicitudes (máximo 60 min)</option></select></div>
<div class="field"><label for="noise">Nivel de ruido</label><select id="noise"><option value="normal">Normal</option><option value="low">Bajo</option></select></div></div><details><summary>Opciones avanzadas de proveedores</summary><div class="row"><div class="field"><label for="include">Solo proveedores</label><input id="include" type="text" placeholder="nmap,nuclei…"></div><div class="field"><label for="exclude">Excluir proveedores</label><input id="exclude" type="text" placeholder="nmap,nuclei…"></div></div><p class="helper">Los filtros no instalan herramientas ni garantizan su ejecución.</p></details>
<div class="auth"><input id="authorized" type="checkbox"><label for="authorized">Confirmo que estoy autorizado a evaluar este objetivo y comprendo que debo respetar su alcance.</label></div>
<p id="profile-help" class="muted">Auto elige capacidades según el objetivo. Pasivo solo revisa evidencia local; no hace ingeniería inversa ni pruebas de red. Para ampliar cobertura, selecciona otro perfil y revisa los permisos y herramientas disponibles.</p><p class="muted">Auto decide por cobertura. Los providers son overrides avanzados; detectado no significa ejecutado. 0 hallazgos no significa seguro.</p><p id="status" role="status" aria-live="polite"></p></section>
<section id="result" hidden><div class="section-heading"><h2>Resultados del reconocimiento</h2><span>02 / EVIDENCIA</span></div><div class="summary-grid" aria-label="Resumen de ejecución"><div class="metric"><b id="metric-status">—</b><span>Estado de evaluación</span></div><div class="metric"><b id="metric-findings">—</b><span>Hallazgos respaldados</span></div><div class="metric"><b id="metric-targets">—</b><span>Objetivos evaluados</span></div></div><article class="warn"><h2>Alcance y límites</h2><p>La cobertura no evaluada y las limitaciones aparecen dentro del informe. No se convierten en ausencia de riesgo.</p></article><article><h2>Siguientes pasos recomendados</h2><ol><li>Revisa la cobertura no evaluada: no equivale a ausencia de riesgos.</li><li>Si elegiste Pasivo, prueba Auto solo cuando tengas autorización para ampliar el reconocimiento.</li><li>Consulta la tabla de proveedores: detectado no significa ejecutado; instalar herramientas es una decisión separada.</li><li>Para ingeniería inversa de software se necesita un análisis específico: este reconocimiento de archivos no lo demuestra.</li></ol><p>Conserva el informe y las evidencias para planificar una evaluación posterior dentro del alcance autorizado.</p></article><div id="human"></div><nav id="exports" class="row" aria-label="Descargar evidencias" hidden><button id="save-html" type="button">Descargar informe HTML</button><button id="save-json" type="button">Exportar JSON</button><button id="save-csv" type="button">Exportar CSV</button></nav></section>
<script>
const $=x=>document.getElementById(x), list=x=>$(x).value.split(',').map(v=>v.trim()).filter(Boolean);
let lastReport=null;
function downloadReport(content,type,extension){if(!lastReport)return;const blob=new Blob([content],{type});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='surface-recon-'+lastReport.run_id+'.'+extension;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000)}
$('save-html').onclick=()=>downloadReport('<!doctype html><html lang="es"><head><meta charset="utf-8"><title>Surface_Recon</title><style>body{background:#0d1117;color:#e6edf3;font:15px system-ui;margin:24px}table{border-collapse:collapse;width:100%}th,td{padding:8px;border-bottom:1px solid #30363d}pre{white-space:pre-wrap;overflow-wrap:anywhere}code{color:#79c0ff}</style></head><body>'+lastReport.html+'</body></html>','text/html;charset=utf-8','html');
$('save-json').onclick=()=>downloadReport(JSON.stringify(lastReport.export,null,2),'application/json;charset=utf-8','json');
$('save-csv').onclick=()=>downloadReport(lastReport.csv,'text/csv;charset=utf-8','csv');
$('run').onclick=async()=>{const target=$('target').value.trim();$('result').hidden=true;$('exports').hidden=true;lastReport=null;if(!target){$('status').textContent='Falta el objetivo: escribe una ruta local, URL o host autorizado.';$('target').focus();return}if(!$('authorized').checked){$('status').textContent='Falta la autorización: marca la casilla de confirmación antes de reconocer.';$('authorized').focus();return}
$('run').disabled=true;$('status').textContent='Reconociendo…';try{const body={target,authorized:true,profile:$('profile').value,noise:$('noise').value,include:list('include'),exclude:list('exclude')};
const r=await fetch('/api/assess',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const d=await r.json();if(!r.ok)throw new Error(d.error||'Falló la evaluación');
$('human').innerHTML=d.html;$('metric-status').textContent=d.status==='completed'?'Completo':d.status==='partial'?'Parcial':d.status;$('metric-findings').textContent=String(d.supported_findings);$('metric-targets').textContent=String(d.rows.length);lastReport=d;$('exports').hidden=false;$('result').hidden=false;$('status').textContent='Reconocimiento completado. Revisa cobertura, evidencia y siguientes pasos.'}catch(e){$('status').textContent=e.message}finally{$('run').disabled=false}};
</script><footer class="footer">Surface_Recon · Evidencia antes que conclusiones. La ausencia de hallazgos no demuestra ausencia de riesgo.</footer></main></body></html>"""

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
        def _local_request(self):
            host = self.headers.get("Host", "").split(":")[0].lower()
            origin = self.headers.get("Origin")
            return host in {"127.0.0.1", "localhost"} and (not origin or origin.rstrip("/") in {f"http://127.0.0.1:{self.server.server_port}", f"http://localhost:{self.server.server_port}"})
        def do_GET(self):
            if not self._local_request():
                self.send_error(403); return
            if self.path not in {"/", "/index.html"}:
                self.send_error(404); return
            raw = _HTML.encode("utf-8")
            self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",str(len(raw))); self.send_header("Cache-Control","no-store"); self.send_header("X-Content-Type-Options","nosniff"); self.end_headers(); self.wfile.write(raw)
        def do_POST(self):
            if not self._local_request():
                self.send_error(403); return
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
            self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8"); self.send_header("Content-Length",str(len(raw))); self.send_header("Cache-Control","no-store"); self.send_header("X-Content-Type-Options","nosniff"); self.end_headers(); self.wfile.write(raw)
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
