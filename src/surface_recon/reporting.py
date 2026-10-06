"""Human report and reusable exports from the same traceable semantic view."""
import csv
from datetime import datetime, timezone
from html import escape
import io
import json
from pathlib import Path
import uuid

from .redaction import minimize
from .results import _jsonable, _surface_data


def human_error(error):
    text = str(error)
    lowered = text.lower()
    if any(s in lowered for s in ("errno 2", "winerror 2", "no such file", "filenotfound")):
        return "No se encontró el archivo o ejecutable. Comprueba que la ruta existe y que el provider está disponible."
    if any(s in lowered for s in ("errno 13", "winerror 5", "permission denied", "access is denied")):
        return "No hay permiso de lectura o ejecución. Revisa los permisos del objetivo o provider."
    if any(s in lowered for s in ("getaddrinfo", "name or service not known", "nodename nor servname", "errno 11001")):
        return "No se pudo resolver el nombre del host. Comprueba el nombre y la conexión DNS."
    if "timed out" in lowered or "timeout" in lowered:
        return "La comprobación agotó su tiempo. La cobertura queda parcial; no demuestra ausencia de riesgo."
    if "connection refused" in lowered or "winerror 10061" in lowered:
        return "El servicio rechazó la conexión en el puerto comprobado."
    return text


def export_payload(assessment):
    return minimize({"schema": "surface-recon-export-v1", "run_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "authorization": "Submitted scope requires renewed explicit authorization before continuation.",
        "assessment": _jsonable(assessment), "rows": _jsonable(_surface_data(assessment))})


def csv_export(payload):
    buffer = io.StringIO(newline="")
    columns = ["run_id", "target", "category", "value", "state", "reason", "evidence_ids", "observation_ids"]
    writer = csv.DictWriter(buffer, fieldnames=columns)
    writer.writeheader()
    def emit(row, category, value, state="", reason="", evidence=(), observations=()):
        values = [payload["run_id"], row["target"], category, value, state, reason,
                  ";".join(evidence), ";".join(observations)]
        # Spreadsheet formula injection protection, while JSON preserves exact values.
        values = ["'" + str(v) if str(v).lstrip().startswith(("=", "+", "-", "@")) else v for v in values]
        writer.writerow(dict(zip(columns, values)))
    for row in payload["rows"]:
        for item in row["surface"]:
            emit(row, "service" if item.get("port") else "surface", item.get("value"),
                 item.get("identity_confidence", "observed"), item.get("priority_reason") or item.get("why"), item.get("evidence_ids", []))
        for item in row["resources"]:
            emit(row, "endpoint", item["url"], item.get("status"), item.get("source"), item.get("evidence_ids", []))
        for item in row["findings"]:
            emit(row, "finding", item["description"], item["status"], item.get("context"), item["evidence_ids"], item["observation_ids"])
        for item in row["hypotheses"]:
            emit(row, "hypothesis", item.get("url") or item.get("endpoint") or item.get("hypothesis"), "unconfirmed", item.get("reason"), item.get("evidence_ids", []))
        for item in row.get("discarded", []):
            emit(row, "discarded", item.get("url") or item.get("candidate_url"), "negative", item.get("reason"), item.get("evidence_ids", []))
        for state in ("evaluated", "unevaluated"):
            for capability in row[state]:
                emit(row, "coverage", capability, state, "Evidence-scoped; zero findings does not mean safe.")
        for item in row.get("lifecycle", []):
            emit(row, "provider", item.get("tool") or item.get("name"), "executed" if item.get("executed") else "skipped", item.get("reason"), item.get("evidence_ids", []))
    return buffer.getvalue()


def write_exports(path, assessment, *, payload=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = payload or export_payload(assessment)
    json_path, csv_path = path.with_suffix(".json"), path.with_suffix(".csv")
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    csv_path.write_text(csv_export(payload), encoding="utf-8-sig")
    return json_path, csv_path


def continuation_scope(payload):
    if payload.get("schema") != "surface-recon-export-v1":
        raise ValueError("La continuación requiere un export JSON de Surface_Recon v1.")
    targets = payload.get("assessment", {}).get("targets", [])
    if not targets or any(not isinstance(t.get("value"), str) or not t["value"].strip()
                          or t.get("scope_state") != "authorized" for t in targets):
        raise ValueError("El export no conserva un alcance original autorizado válido.")
    # Discovered hosts/references are never promoted to new authorization scope.
    return [t["value"] for t in targets]


def continuation_targets(path):
    return continuation_scope(json.loads(Path(path).read_text(encoding="utf-8")))


STYLE = """body{font-family:Segoe UI,Arial,sans-serif;background:#0d1117;color:#e6edf3;margin:0}main{max-width:1180px;margin:auto;padding:24px}article,.panel{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin:12px 0}table{width:100%;border-collapse:collapse;table-layout:fixed}th,td{text-align:left;vertical-align:top;padding:9px;border-bottom:1px solid #30363d;overflow-wrap:anywhere}th{color:#79c0ff}p,li{line-height:1.5}code{color:#79c0ff;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:400px;overflow:auto}small,.muted{color:#adb9c7}details{margin:12px 0}summary{cursor:pointer}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}a{color:#79c0ff}button,input,select{padding:9px;margin:5px;max-width:100%;box-sizing:border-box}h2{overflow-wrap:anywhere}@media(max-width:600px){main{padding:12px}th,td{padding:5px;font-size:13px}}"""


def table(headers, rows):
    def cell(value):
        if isinstance(value, (list, tuple)):
            value = "; ".join(str(x) for x in value)
        return escape(str(value if value is not None else "—"))
    content = "".join("<tr>" + "".join(f"<td>{cell(v)}</td>" for v in row) + "</tr>" for row in rows)
    return "<table><thead><tr>" + "".join(f"<th>{cell(h)}</th>" for h in headers) + "</tr></thead><tbody>" + content + "</tbody></table>" if content else "<p class='muted'>Sin evidencia observada en esta categoría.</p>"


def report_body(payload):
    assessment = payload["assessment"]
    parts = [f"<p>Estado: <b>{escape(assessment['status'])}</b> · Ejecución: <code>{escape(payload['run_id'])}</code></p>",
             "<p>0 hallazgos no significa que el objetivo sea seguro. La cobertura es limitada a las comprobaciones demostradas.</p>"]
    evidence = {x["id"]: x for x in assessment["evidence"]}
    for row in payload["rows"]:
        parts.append(f"<section><h2>{escape(row['target'])}</h2><p>Tipo: {escape(str(row['type']))}</p>")
        hosts = {}
        for item in row["observed"]:
            data = item["evidence"]
            if data.get("kind") == "host":
                hosts.setdefault(data.get("host"), []).extend(item.get("evidence_ids", []))
            if data.get("kind") in {"network-hosts", "nmap-host-discovery", "nmap-surface"}:
                for host in data.get("hosts", []):
                    addresses = (host.get("addresses") or [host.get("address")]) if isinstance(host, dict) else [host]
                    for address in addresses:
                        if address:
                            hosts.setdefault(address, []).extend(item.get("evidence_ids", []))
        for s in row["surface"]:
            if s.get("host"):
                hosts.setdefault(s["host"], []).extend(s.get("evidence_ids", []))
        parts += ["<article><h3>Hosts observados</h3>", table(["Host", "Servicios", "Evidencia"],
            [(h, sum(s.get("host") == h for s in row["surface"]), sorted(set(ids))) for h, ids in hosts.items()]), "</article>"]
        services = [s for s in row["surface"] if s.get("port")]
        parts += ["<article><h3>Servicios y endpoints de red</h3>", table(
            ["Endpoint", "Servicio / producto", "Confianza", "Prioridad / siguiente paso", "Evidencia"],
            [(s["value"], " ".join(str(s.get(k) or "") for k in ("service", "product", "version")),
              s.get("identity_confidence"), (s.get("review_priority") or "") + ": " + (s.get("priority_reason") or s.get("why") or ""),
              s.get("evidence_ids") or s.get("evidence_sources", [])) for s in services]), "</article>"]
        parts += ["<article><h3>Endpoints HTTP</h3>", table(["URL", "HTTP", "Tipo", "Origen / evidencia"],
            [(x["url"], x["status"], x["kind"], str(x.get("source") or "entrada") + " · " + ", ".join(x.get("evidence_ids", [])))
             for x in row["resources"] if x["kind"] != "asset"]), "</article>"]
        parts += ["<article><h3>Archivos, artefactos e inventario</h3>"]
        for item in row["observed"]:
            data = item["evidence"]
            kind = data.get("kind")
            if kind == "inventory":
                parts.append(table(["Archivos", "Recursión", "Subdirectorios visitados", "Omitidos", "Frontera", "Evidencia"],
                    [(data.get("file_count"), "sí" if data.get("recursive") else "no registrada", len(data.get("visited_subdirectories", [])),
                      len(data.get("skipped_subdirectories", [])), "agotada dentro de la política" if data.get("frontier_exhausted") else "parcial/no registrada", item.get("evidence_ids", []))]))
                if data.get("zero_files_reason"):
                    parts.append("<p>0 archivos: " + escape(human_error(data["zero_files_reason"])) + "</p>")
                parts.append("<p>Política: dependencias, entornos y archivos generados excluidos; no se siguen enlaces ni junctions.</p>")
                parts.append(table(["Visitados", "Omitidos", "Errores de lectura"], [(data.get("visited_subdirectories", []), data.get("skipped_subdirectories", []), data.get("read_errors", []))]))
            elif kind in {"artifact", "archive-analysis", "pe-static-analysis", "static-analysis", "opaque-target"}:
                parts.append(f"<p>{escape(item['description'])} · evidencia {escape(', '.join(item.get('evidence_ids', [])))}</p>")
        parts.append(table(["Interfaz / referencia", "Por qué", "Evidencia"], [(x.get("value"), x.get("why"), x.get("evidence_ids", [])) for x in row["surface"] if not x.get("port")]))
        parts += ["</article><article><h3>Hallazgos</h3>", table(["Condición", "Estado", "Impacto demostrado / evidencia"],
            [(f["description"], f["status"], "; ".join(str(evidence.get(e, {}).get("content", {}).get("impact_demonstrated") or e) for e in f["evidence_ids"])) for f in row["findings"]]), "</article>"]
        parts += ["<article><h3>Hipótesis activas: requieren validación</h3>"]
        for h in row["hypotheses"]:
            basis = h.get("basis") or {}
            parts.append(f"<p><b>{escape(str(h.get('hypothesis')))}</b> · <code>{escape(str(h.get('url') or h.get('endpoint') or ''))}</code><br>{escape(str(h.get('reason') or ''))}<br>Base concreta: {escape(str(basis.get('url') or basis.get('endpoint') or h.get('url') or h.get('endpoint') or ''))}; tokens: {escape(', '.join(basis.get('triggers', [])))}; evidencia: {escape(', '.join(h.get('evidence_ids', [])))}</p>")
            recipe = h.get("validation_recipe") or {}
            parts.append(table(["Clase", "Objetivo seguro"], [(c.get("class"), c.get("objective")) for c in recipe.get("checks", [])]))
            if recipe.get("success_rule"):
                parts.append("<p>Regla de promoción: " + escape(recipe["success_rule"]) + "</p>")
        parts += ["</article><article><h3>Cobertura y qué falta comprobar</h3>", table(["Subcapacidad", "Estado"],
            [(x, "evaluada") for x in row["evaluated"]] + [(x, "no evaluada") for x in row["unevaluated"]])]
        for item in row["observed"]:
            data = item["evidence"]
            if data.get("tested_ports"):
                parts.append("<p>Puertos comprobados: " + escape(", ".join(map(str, data["tested_ports"]))) + "; rango TCP completo: " + ("sí" if data.get("full_tcp_range_tested") else "no") + "</p>")
        for d in row["decisions"]:
            if d.get("requests") is not None:
                parts.append(f"<p>HTTP: {d['requests']} solicitudes; límite {d.get('budget')}; candidatos restantes {d.get('remaining_candidates')}; motivo {escape(str(d.get('stop_reason')))}.</p>")
        for limit in row.get("limitations", []):
            parts.append("<p>Limitación: " + escape(human_error(limit["reason"])) + " · " + escape(limit["impact"]) + "</p>")
        parts += ["</article><article><h3>Providers: detectado → seleccionado → ejecutado</h3>", table(
            ["Provider", "Detectado", "Seleccionado", "Ejecutado", "Omitido / motivo"],
            [(x.get("tool") or x.get("name"), "sí" if x.get("detected") else "no", "sí" if x.get("selected") else "no", "sí" if x.get("executed") else "no", human_error(x.get("reason") or "")) for x in row.get("lifecycle", [])]),
            "<p>Las capacidades internas y sus evidencias también se conservan en el export. Detectado no significa ejecutado ni cobertura completa.</p></article>"]
        parts.append("<details><summary>Evidencia secundaria JSON y descartados</summary><pre>" + escape(json.dumps(row, ensure_ascii=False, indent=2)) + "</pre></details></section>")
    return "".join(parts)


def write_human_report(path, assessment, *, payload=None):
    path = Path(path)
    payload = payload or export_payload(assessment)
    write_exports(path, assessment, payload=payload)
    html = "<!doctype html><html lang='es'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Surface_Recon · Informe</title><style>" + STYLE + "</style></head><body><main><h1>Surface_Recon</h1>"
    html += f"<p><a download href='{escape(path.with_suffix('.json').name, quote=True)}'>Exportar JSON</a> · <a download href='{escape(path.with_suffix('.csv').name, quote=True)}'>Exportar CSV</a></p>"
    html += report_body(payload) + "<footer>LAB/Product PENDING. HUMAN QA sigue siendo un gate humano.</footer></main></body></html>"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return path
