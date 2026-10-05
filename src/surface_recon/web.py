"""Local interactive Surface_Recon UI.

This is a loopback-only product surface recovered from the validated LAB-001
clean-room experiment and adapted to the current assessment engine.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import webbrowser

from .assessment import assess_targets
from .redaction import minimize
from .results import _jsonable, _surface_data

_HTML = r"""<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Surface_Recon</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;background:#0d1117;color:#e6edf3;margin:0}main{max-width:1100px;margin:auto;padding:36px}.panel,article{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin:12px 0}.row{display:flex;gap:8px}.row input{flex:1;padding:10px}button{padding:10px 16px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px}.muted{color:#8b949e}code{color:#79c0ff;overflow-wrap:anywhere}li{margin:7px 0}.warn{border-left:4px solid #f0883e}</style></head>
<body><main><header><small>IA DIRECTOR · LAB-001</small><h1>Surface_Recon</h1><p>Reconocimiento autónomo orientado a evidencia para objetivos que estás autorizado a evaluar.</p></header>
<section class="panel"><label for="target">Objetivo autorizado</label><div class="row"><input id="target" placeholder="URL, host, red, archivo, directorio o repositorio"><button id="run">Reconocer</button></div>
<label><input id="authorized" type="checkbox"> Confirmo que estoy autorizado a evaluar este objetivo.</label><p class="muted">La interfaz distingue evidencia, cobertura, gaps e hipótesis. Cobertura parcial nunca se presenta como evaluación completa.</p><p id="status"></p></section>
<section id="result" hidden><div class="grid"><article><h2>Resumen</h2><div id="summary"></div></article><article><h2>Cobertura</h2><div id="coverage"></div></article></div><article class="warn"><h2>Gaps / siguientes fases</h2><div id="gaps"></div></article><article><h2>Superficie y evidencia</h2><div id="surface"></div></article></section>
<script>
const $=x=>document.getElementById(x), esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
$('run').onclick=async()=>{const target=$('target').value.trim();$('result').hidden=true;if(!target||!$('authorized').checked){$('status').textContent='Ingresa un objetivo y confirma autorización.';return}$('run').disabled=true;$('status').textContent='Reconociendo…';
try{const r=await fetch('/api/assess',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target,authorized:true})});const d=await r.json();if(!r.ok)throw new Error(d.error||'Falló la evaluación');
$('summary').innerHTML='<b>Estado:</b> '+esc(d.status)+'<br><b>Tipo:</b> '+esc(d.rows[0]?.type||'unresolved')+'<br><b>Hallazgos soportados:</b> '+esc(d.supported_findings);
$('coverage').innerHTML=d.rows.map(x=>'<p><b>'+esc(x.target)+'</b><br>Evaluado: '+esc(x.evaluated.join(', ')||'nada')+'<br>No evaluado: '+esc(x.unevaluated.join(', ')||'nada')+'</p>').join('');
$('gaps').innerHTML=d.rows.map(x=>(x.next||[]).map(n=>'<p><b>'+esc(n.capability)+'</b>: falta '+esc(n.missing.join(', '))+'<br>'+esc(n.reason)+'</p>').join('')).join('')||'<p>No hay gaps modelados adicionales. Esto no equivale a objetivo seguro.</p>';
$('surface').innerHTML=d.rows.map(x=>'<h3>'+esc(x.target)+'</h3>'+(x.surface||[]).map(s=>'<p><code>'+esc(s.value)+'</code><br>'+esc(s.why)+'</p>').join('')+(x.observed||[]).map(o=>'<details><summary>'+esc(o.description)+'</summary><pre>'+esc(JSON.stringify(o.evidence,null,2))+'</pre></details>').join('')).join('');
$('result').hidden=false;$('status').textContent='Reconocimiento completado. Revisa evidencia y gaps juntos.'}catch(e){$('status').textContent=e.message}finally{$('run').disabled=false}};
</script></main></body></html>"""

def inspect_authorized(target: str, *, authorized: bool, use_extensions: bool = True) -> dict:
    target = str(target).strip()
    if not target or authorized is not True:
        raise ValueError("Target and explicit authorization are required.")
    assessment = assess_targets([target], use_extensions=use_extensions)
    rows = minimize(_jsonable(_surface_data(assessment)))
    supported = sum(1 for finding in assessment.findings if getattr(finding.status, "value", finding.status) == "supported")
    return {"status": assessment.status.value, "supported_findings": supported, "rows": rows}

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
                if length < 1 or length > 8192:
                    raise ValueError("Invalid request size.")
                body = json.loads(self.rfile.read(length))
                payload = inspect_authorized(body.get("target",""), authorized=body.get("authorized") is True, use_extensions=use_extensions)
                raw = json.dumps(payload, ensure_ascii=False).encode("utf-8"); status=200
            except Exception as exc:
                raw = json.dumps({"error": str(exc)}, ensure_ascii=False).encode("utf-8"); status=400
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
