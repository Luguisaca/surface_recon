"""Local structured result persistence. No database is used."""

from dataclasses import asdict, is_dataclass
from enum import Enum
import json
from pathlib import Path
from typing import Any

from .redaction import minimize


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return _jsonable(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def write_result(path: Path, result: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = minimize(_jsonable(result))
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def read_result(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def render_assessment(assessment: Any) -> str:
    """Render target classification, status, coverage and limitations."""
    coverage_by_target = {item.target_id: item for item in assessment.coverage}
    tools_used = sorted({tool for capability in assessment.capabilities for tool in capability.tools_used})
    evaluated = sorted({item for coverage in assessment.coverage for item in coverage.evaluated})
    plain_names = {
        "http-probing": "HTTP reachability and response metadata",
        "technology-fingerprinting": "technology fingerprint signals",
        "template-detection": "template-based checks configured for this run",
        "inventory": "resource inventory",
        "host-discovery": "host discovery",
        "port-discovery": "port discovery",
        "service-fingerprinting": "service fingerprint signals",
    }

    lines = ["What was actually checked:"]
    if evaluated:
        lines.extend(f"  - {plain_names.get(item, item.replace('-', ' '))}" for item in evaluated)
    else:
        lines.append("  - no technical subcapability was successfully evaluated")

    lines.append("Result:")
    if assessment.findings:
        supported = sum(
            1 for finding in assessment.findings
            if getattr(finding.status, "value", finding.status) == "supported"
        )
        potential = len(assessment.findings) - supported
        if supported:
            lines.append(f"  - {supported} evidence-supported risk finding(s) reported.")
        if potential:
            lines.append(f"  - {potential} potential/unconfirmed risk finding(s) reported.")
        lines.append("  - See traceable evidence below.")
    else:
        lines.append("  - No risk finding was reported by the executed tooling within evaluated coverage.")
        lines.append("  - This does not mean the target is secure.")

    if any(coverage.unevaluated for coverage in assessment.coverage):
        lines.append("  - Coverage has explicit gaps; see Not evaluated below.")

    lines.extend([
        "",
        "Technical detail:",
        f"Assessment: {assessment.id}",
        f"Status: {assessment.status.value}",
        "",
    ])
    if tools_used:
        lines.append(f"Tools used: {', '.join(tools_used)}")
        lines.append("")

    for target in assessment.targets:
        lines.append(f"Target: {target.value}")
        lines.append(f"  Type: {target.target_type or 'unresolved'}")

        target_capabilities = [cap for cap in assessment.capabilities if cap.target_id == target.id]
        if target_capabilities:
            from .tooling import candidates_for
            lines.append("  Tool provenance:")
            for capability in target_capabilities:
                catalog = {item.id: item for item in candidates_for(capability.id)}
                if not capability.tools_used:
                    lines.append(f"    - {capability.id}: no tool executed successfully")
                for tool_id in capability.tools_used:
                    candidate = catalog.get(tool_id)
                    if tool_id == "surface-recon-core":
                        purpose = "Owned evidence-first reconnaissance and interpretation."
                        covered = "demonstrated coverage is reflected in the target coverage section"
                    else:
                        purpose = candidate.purpose if candidate else "Purpose not recorded."
                        covered = (
                            ", ".join(candidate.subcapabilities)
                            if candidate and candidate.subcapabilities
                            else "not recorded"
                        )
                    lines.append(f"    - {tool_id} — {purpose}")
                    lines.append(f"      Covered by this tool: {covered}")

        if target.discovered_resources:
            lines.append(
                f"  Discovered/followed resources within submitted target context: "
                f"{len(target.discovered_resources)}"
            )
            for resource in target.discovered_resources[:5]:
                lines.append(f"    - {resource}")
            if len(target.discovered_resources) > 5:
                lines.append(f"    … {len(target.discovered_resources) - 5} additional resource(s)")

        coverage = coverage_by_target.get(target.id)
        if coverage:
            evaluated = ", ".join(coverage.evaluated) or "none"
            unevaluated = ", ".join(coverage.unevaluated) or "none"
            lines.append(f"  Evaluated: {evaluated}")
            lines.append(f"  Not evaluated: {unevaluated}")
            if not coverage.unevaluated:
                lines.append(
                    "  Coverage note: complete only for the modeled subcapabilities above; "
                    "this is not a complete security assessment."
                )

            for limitation in coverage.limitations:
                reason = limitation.reason.lower()
                if "unavailable" in reason or "unsupported" in reason:
                    state = "unavailable"
                elif "failed" in reason:
                    state = "failed"
                else:
                    state = "partial"
                lines.append(f"  Coverage state: {state}")
                lines.append(f"  Limitation: {limitation.reason}")
                lines.append(f"  Impact: {limitation.impact}")
                if state == "unavailable" and limitation.capability_id:
                    from .tooling import recommendations_for
                    recommendations = recommendations_for(limitation.capability_id)
                    if recommendations:
                        lines.append("  Recommended tools (not installed automatically):")
                        for item in recommendations:
                            lines.append(f"    - {item.tool_id}: {item.purpose}")
                            lines.append(f"      {item.compatibility}")
                            lines.append(f"      License: {item.license_note}")

        lines.append("")

    evidence_by_id = {item.id: item for item in assessment.evidence}
    if assessment.observations:
        lines.append("Observed conditions:")
        for observation in assessment.observations:
            lines.append(f"  - {observation.description}")
            lines.append(f"    Evidence: {', '.join(observation.evidence_ids) or 'none'}")
            for evidence_id in observation.evidence_ids:
                evidence = evidence_by_id.get(evidence_id)
                if evidence:
                    lines.append(f"      {evidence.source}: {minimize(evidence.content)}")

    lines.append("Potential risks / findings:")
    if assessment.findings:
        for finding in assessment.findings:
            lines.append(f"  - [{finding.status.value}] {finding.description}")
            lines.append(f"    Evidence: {', '.join(finding.evidence_ids) or 'none'}")
            for evidence_id in finding.evidence_ids:
                evidence = evidence_by_id.get(evidence_id)
                if evidence:
                    lines.append(f"      {evidence.source}: {minimize(evidence.content)}")
    else:
        lines.append("  - none reported by executed tooling within evaluated coverage")
        lines.append("    This does not establish that the target is secure.")

    return "\n".join(lines).rstrip()


def render_findings(
    findings: list[Any],
    observations: list[Any],
    evidence: list[Any],
) -> str:
    """Render findings with traceability and minimized evidence."""
    if not findings:
        return (
            "Supported findings: 0\n"
            "No supported findings were observed within evaluated coverage. "
            "This does not establish that the target is secure."
        )

    evidence_by_id = {item.id: item for item in evidence}
    supported = sum(f.status.value == "supported" for f in findings)
    potential = sum(f.status.value != "supported" for f in findings)
    lines = [
        f"Sustentados por evidencia disponible: {supported}",
        f"Potenciales / no confirmados: {potential}",
    ]

    for finding in findings:
        lines.append("")
        if finding.status.value == "supported":
            lines.append(f"CONFIRMED BY EVIDENCE: {finding.description}")
            lines.append("  Meaning: observed condition with supporting evidence.")
        else:
            lines.append(f"POTENTIAL — NOT CONFIRMED: {finding.description}")
            lines.append("  Meaning: a signal was observed, but evidence is insufficient to confirm it.")
        lines.append(f"  Observation references: {', '.join(finding.observation_ids) or 'none'}")
        lines.append(f"  Evidence references: {', '.join(finding.evidence_ids) or 'none'}")

        for evidence_id in finding.evidence_ids:
            item = evidence_by_id.get(evidence_id)
            if item is not None:
                lines.append(f"    {evidence_id}: {minimize(item.content)!r}")

    return "\n".join(lines)


def render_surface_map(assessment: Any) -> str:
    """Human-facing attack-surface view for the owned reconnaissance core."""
    evidence_by_id = {item.id: item for item in assessment.evidence}
    lines = ["Surface_Recon — attack surface", ""]

    for target in assessment.targets:
        lines.append(f"Target: {target.value}")
        target_observations = [item for item in assessment.observations if item.target_id == target.id]
        urls: list[tuple[int | None, str, str | None, str, str | None]] = []
        addresses: list[str] = []
        signals: list[str] = []

        for observation in target_observations:
            for evidence_id in observation.evidence_ids:
                evidence = evidence_by_id.get(evidence_id)
                if not evidence or not isinstance(evidence.content, dict):
                    continue
                data = evidence.content
                if data.get("addresses"):
                    addresses.extend(str(item) for item in data["addresses"])
                if data.get("signals"):
                    signals.extend(str(item) for item in data["signals"])
                if data.get("url"):
                    urls.append((data.get("status"), str(data["url"]), data.get("content_type"), str(data.get("kind") or "resource"), data.get("discovered_from")))

        if addresses:
            lines.append("Resolved addresses:")
            for address in sorted(set(addresses)):
                lines.append(f"  - {address}")

        if signals:
            lines.append("Technology signals:")
            for signal in sorted(set(signals)):
                lines.append(f"  - {signal}")

        meaningful = [item for item in urls if item[3] not in {"asset", "hypothesis", "security-hypothesis", "not_found", "control"}]
        static_count = sum(1 for item in urls if item[3] == "asset")
        order = {"interesting": 0, "metadata": 1, "page": 2, "entrypoint": 2, "script": 3, "resource": 4}
        meaningful.sort(key=lambda item: (order.get(item[3], 5), item[1]))
        lines.append("Relevant observed surface:")
        if meaningful:
            seen: set[str] = set()
            for status, url, content_type, kind, source in meaningful:
                if url in seen:
                    continue
                seen.add(url)
                suffix = f" · {content_type}" if content_type else ""
                relation = f" · from {source}" if source and kind != "entrypoint" else ""
                lines.append(f"  - {kind.upper():11} [{status if status is not None else '?'}] {url}{suffix}{relation}")
        else:
            lines.append("  - none")
        if static_count:
            lines.append(f"Static assets suppressed from this view: {static_count}")

        target_coverage = next((item for item in assessment.coverage if item.target_id == target.id), None)
        if target_coverage:
            lines.append("Coverage:")
            lines.append("  Checked: " + (", ".join(target_coverage.evaluated) or "none"))
            lines.append("  Still not evaluated: " + (", ".join(target_coverage.unevaluated) or "none"))

        target_findings = [item for item in assessment.findings if item.target_id == target.id]
        lines.append(f"Evidence-backed risk findings: {len(target_findings)}")
        for finding in target_findings:
            lines.append(f"  - [{finding.status.value}] {finding.description}")
        lines.append("")

    lines.append("Note: this maps observed surface; missing findings do not mean the target is secure.")
    return "\n".join(lines).rstrip()


def _surface_data(assessment: Any) -> list[dict[str, Any]]:
    evidence_by_id = {item.id: item for item in assessment.evidence}
    output: list[dict[str, Any]] = []
    for target in assessment.targets:
        row: dict[str, Any] = {"target_id": target.id, "target": target.value, "type": target.target_type, "addresses": [], "signals": [], "resources": [], "decisions": [], "hypotheses": [], "observed": [], "surface": [], "executions": [], "providers": [], "lifecycle": [], "discarded": [], "tools": [], "next": []}
        for observation in assessment.observations:
            if observation.target_id != target.id:
                continue
            for evidence_id in observation.evidence_ids:
                evidence = evidence_by_id.get(evidence_id)
                if not evidence or not isinstance(evidence.content, dict):
                    continue
                data = {**evidence.content, "evidence_ids": [evidence_id], "observation_ids": [observation.id]}
                row["addresses"].extend(str(x) for x in data.get("addresses", []))
                row["signals"].extend(str(x) for x in data.get("signals", []))
                if data.get("url") and data.get("kind") not in {"hypothesis", "discarded-hypothesis", "security-hypothesis", "security-finding", "not_found", "control"}:
                    row["resources"].append({
                        "url": str(minimize(data["url"])), "status": data.get("status"),
                        "content_type": data.get("content_type"), "kind": str(data.get("kind") or "resource"),
                        "source": minimize(data.get("discovered_from")), "fetched": data.get("fetched", True), "evidence_ids": [evidence_id],
                    })
                if data.get("kind") == "execution":
                    row["executions"].append(minimize(data))
                if data.get("kind") == "provider-lifecycle":
                    row["lifecycle"].append(minimize(data))
                if data.get("kind") in {"not_found", "discarded-hypothesis"} or data.get("status") in {404, 410}:
                    row["discarded"].append(minimize(data))
                if data.get("kind") == "environment-providers":
                    row["providers"].extend(minimize(data.get("providers", [])))
                if data.get("kind") == "decision":
                    row["decisions"].append(data)
                if data.get("kind") in {"hypothesis", "security-hypothesis"}:
                    row["hypotheses"].append({**minimize(data), "evidence_ids": [evidence_id], "observation_id": observation.id})
                if data.get("kind") in {"artifact", "artifact-references", "pe-static-analysis", "archive-analysis", "inventory", "ports", "host", "network", "network-hosts", "service-fingerprints", "opaque-target", "static-analysis", "nmap-host-discovery", "nmap-surface"}:
                    row["observed"].append({"description": observation.description, "evidence": minimize(data), "evidence_ids": [evidence_id]})
                kind = data.get("kind")
                if kind == "ports":
                    for service in data.get("reachable", []):
                        row["surface"].append({"type":"network-service","value":f"{data.get('host')}:{service.get('port')}",
                            "evidence":service,"why":"TCP endpoint observed reachable"})
                elif kind == "service-fingerprints":
                    for service in data.get("services", []):
                        row["surface"].append({"type":"service-interface","value":f"{data.get('host')}:{service.get('port')}",
                            "evidence":service,"why":"reachable service selected for protocol fingerprinting"})
                elif kind == "artifact-references":
                    for url in data.get("urls", []):
                        row["surface"].append({"type":"external-reference","value":str(minimize(url)),
                            "evidence":{"source":"artifact-string"},"why":"artifact contains an external endpoint/reference"})
                elif kind == "pe-static-analysis":
                    for imp in data.get("imports", []):
                        name = imp.get("library") if isinstance(imp, dict) else str(imp)
                        row["surface"].append({"type":"binary-dependency","value":str(name),
                            "evidence":imp,"why":"imported dependency expands the artifact trust/interface boundary"})
                        if isinstance(imp, dict):
                            for symbol in imp.get("symbols", [])[:100]:
                                row["surface"].append({"type":"imported-interface","value":f"{name}!{symbol}",
                                    "evidence":{"library":name,"symbol":symbol},
                                    "why":"imported API is an executable interface used by the artifact"})
                            if str(name).lower() == "mscoree.dll":
                                row["surface"].append({"type":"managed-runtime","value":".NET CLR",
                                    "evidence":imp,"why":"CLR bootstrap import indicates managed-code metadata/runtime is relevant"})
                elif kind == "archive-analysis":
                    for entry in data.get("entries", [])[:100]:
                        row["surface"].append({"type":"contained-artifact","value":str(entry),
                            "evidence":{"container":target.value},"why":"contained object may expose additional interfaces"})
                elif kind == "inventory":
                    for manifest in data.get("manifests", []):
                        row["surface"].append({"type":"dependency-manifest","value":str(manifest),
                            "evidence":{"root":target.value},"why":"manifest defines external components/dependencies"})
                elif kind == "nmap-surface":
                    for host in data.get("hosts", []):
                        address = (host.get("addresses") or [target.value])[0]
                        for service in host.get("services", []):
                            label = f"{address}:{service.get('port')}/{service.get('protocol') or 'tcp'}"
                            product = " ".join(str(x) for x in (service.get("service"), service.get("product"), service.get("version")) if x)
                            fingerprinted = bool(
                                service.get("product") or service.get("version")
                                or service.get("method") == "probed"
                            )
                            surface_type = "fingerprinted-service" if fingerprinted else "open-port"
                            identity = (
                                f"fingerprint evidence: {product}" if fingerprinted
                                else f"provider service hint (not a verified fingerprint): {product or 'unknown'}"
                            )
                            row["surface"].append({"type":surface_type,"value":label,
                                "evidence":service,"why":f"open TCP service observed by provider; {identity}"})
        # Human-facing network surface is semantic, not a concatenation of raw
        # core/provider rows. Raw observations above remain preserved as evidence.
        if target.target_type in {"host", "network"}:
            from .surface_model import merge_service_surface, prioritize_service_surface
            raw_for_model = []
            for observation in assessment.observations:
                if observation.target_id != target.id:
                    continue
                for evidence_id in observation.evidence_ids:
                    evidence = evidence_by_id.get(evidence_id)
                    if evidence and isinstance(evidence.content, dict):
                        raw_for_model.append({"source": evidence.source, "evidence": evidence.content, "evidence_id": evidence_id})
            semantic_services = prioritize_service_surface(merge_service_surface(raw_for_model, target.value))
            non_service = [x for x in row["surface"] if x.get("type") not in {"network-service", "service-interface", "fingerprinted-service", "open-port"}]
            row["surface"] = [*non_service, *semantic_services]

        rejected_hypothesis_urls = {
            str(item.get("url")) for item in row["decisions"]
            if item.get("reason") == "soft-not-found" and item.get("url")
        }
        rejected_hypothesis_urls.update(
            str(evidence.content.get("url"))
            for observation in assessment.observations if observation.target_id == target.id
            for evidence_id in observation.evidence_ids
            for evidence in [evidence_by_id.get(evidence_id)]
            if evidence and isinstance(evidence.content, dict)
            and (evidence.content.get("kind") == "not_found" or evidence.content.get("status") in {404, 410}) and evidence.content.get("url")
        )
        rejected_hypothesis_urls.update(str(item["candidate_url"]) for item in row["discarded"] if item.get("candidate_url"))
        rejected_hypothesis_urls.update(
            str(item.get("url")) for item in row["resources"]
            if item.get("status") in {404, 410} and item.get("url")
        )
        if rejected_hypothesis_urls:
            rejected_hypothesis_urls.update(str(item["candidate_url"]) for item in row["discarded"] if item.get("candidate_url"))
            row["discarded"].extend({**item, "disposition": "discarded-hypothesis"} for item in row["hypotheses"] if str(item.get("url")) in rejected_hypothesis_urls)
            row["resources"] = [item for item in row["resources"] if item["url"] not in rejected_hypothesis_urls]
            row["hypotheses"] = [
                item for item in row["hypotheses"]
                if not item.get("url") or str(item.get("url")) not in rejected_hypothesis_urls
            ]

        coverage = next((x for x in assessment.coverage if x.target_id == target.id), None)
        row["evaluated"] = list(coverage.evaluated) if coverage else []
        row["unevaluated"] = list(coverage.unevaluated) if coverage else []
        row["limitations"] = _jsonable(coverage.limitations) if coverage else []
        row["findings"] = [x for x in assessment.findings if x.target_id == target.id]
        caps = [x for x in assessment.capabilities if x.target_id == target.id]
        row["tools"] = sorted({tool for cap in caps for tool in cap.tools_used})
        if coverage and coverage.unevaluated:
            from .tooling import recommendations_for
            for cap in caps:
                missing = [x for x in cap.required_subcapabilities if x in coverage.unevaluated]
                if not missing:
                    continue
                recs = recommendations_for(cap.id, missing)
                relevant_providers = [
                    provider for provider in row["providers"]
                    if set(provider.get("subcapabilities", [])).intersection(missing)
                ]
                row["next"].append({
                    "capability": cap.id, "missing": missing,
                    "tools": [r.tool_id for r in recs],
                    "providers": relevant_providers,
                    "reason": "Cobertura pendiente; no puede inferirse ausencia de riesgo.",
                })
        output.append(row)
    return output


def render_surface_map(assessment: Any) -> str:
    """Resumen en español para consola; el informe HTML contiene el detalle."""
    labels = {"interesting": "SUPERFICIE PRIORITARIA", "metadata": "METADATO", "page": "PÁGINA",
              "entrypoint": "ENTRADA", "script": "SCRIPT", "resource": "RECURSO"}
    why = {
        "interesting": "Puede representar autenticación, administración, API o telemetría; merece revisión.",
        "metadata": "Describe o condiciona cómo se publica/rastrea el sitio.",
        "page": "Superficie navegable observada.",
        "entrypoint": "Punto inicial autorizado del reconocimiento.",
        "script": "Código cliente; puede revelar rutas, APIs y relaciones adicionales.",
        "resource": "Recurso observado sin clasificación más específica.",
    }
    lines = ["Surface_Recon — resumen para auditor", ""]
    for row in _surface_data(assessment):
        lines.append(f"OBJETIVO: {row['target']}")
        if row["signals"]:
            lines.append("CONTEXTO TECNOLÓGICO: " + " · ".join(sorted(set(row["signals"]))))
        if row["addresses"]:
            lines.append("DIRECCIONES OBSERVADAS: " + ", ".join(sorted(set(row["addresses"]))))
        if any("cloudflare" in x.lower() for x in row["signals"]):
            lines.append("INTERPRETACIÓN: Cloudflare está delante del sitio; estas IP observadas pueden corresponder al edge y no prueban el origen.")
        if any(x.lower() == "astro" for x in row["signals"]):
            lines.append("INTERPRETACIÓN: se observan señales de Astro; los scripts cliente son una fuente útil para buscar rutas/servicios relacionados.")
        evidence_plans = [
            item for item in row["decisions"]
            if item.get("reason") == "evidence-derived-validation-plan"
        ]
        provider_skips = [
            item for item in row["decisions"]
            if item.get("reason") == "provider-coverage-not-demonstrated"
        ]
        if row["hypotheses"] or evidence_plans or provider_skips:
            lines.append("")
            lines.append("DECISIONES AUTÓNOMAS:")
            grouped: dict[str, int] = {}
            for item in row["hypotheses"]:
                name = str(item.get("hypothesis") or "hipótesis")
                grouped[name] = grouped.get(name, 0) + 1
            for name, count in grouped.items():
                lines.append(f"  - {name}: {count} comprobación(es) propuesta(s) a partir de evidencia observada.")
        for plan in evidence_plans:
            required = ", ".join(plan.get("required_subcapabilities", []))
            lines.append(f"  - Planner: evidencia observada hizo pertinente validar: {required}.")
        for skip in provider_skips:
            lines.append(
                f"  - {skip.get('tool')}: no se acreditó cobertura; "
                f"{skip.get('detail') or 'sin evidencia suficiente'}"
            )

        if row["observed"]:
            lines.append("")
            lines.append("CARACTERIZACIÓN:")
            for item in row["observed"]:
                lines.append(f"  - {item['description']}")
                ev = item["evidence"]
                if ev.get("artifact_type"):
                    lines.append(f"    Tipo: {ev['artifact_type']} · Tamaño: {ev.get('size')} bytes")
                    lines.append(f"    SHA-256: {ev.get('sha256')}")
                if ev.get("urls"):
                    lines.append(f"    Referencias URL: {len(ev['urls'])}")
                if ev.get("manifests") is not None:
                    lines.append(f"    Manifiestos: {', '.join(ev['manifests'][:10]) or 'ninguno'}")
                if ev.get("reachable") is not None:
                    ports = [f"{x.get('port')}/{x.get('service_hint', '?')}" for x in ev["reachable"]]
                    lines.append(f"    Puertos TCP alcanzables: {', '.join(ports) or 'ninguno de los comprobados'}")
                    tested = ev.get("tested_ports", [])
                    lines.append(f"    Cobertura TCP exacta: {len(tested)} puerto(s) comprobado(s); rango completo={'sí' if ev.get('full_tcp_range_tested') else 'no'}")
                    if tested and len(tested) <= 30:
                        lines.append("    Puertos comprobados: " + ", ".join(str(x) for x in tested))
                if ev.get("mitigations") is not None:
                    m = ev["mitigations"]
                    lines.append(f"    Mitigaciones PE: ASLR={m.get('aslr')} · DEP/NX={m.get('dep_nx')} · High-entropy VA={m.get('high_entropy_va')} · Firma embebida={m.get('signed_directory_present')}")
                    lines.append(f"    Imports: {len(ev.get('imports', []))} librería(s) · Secciones: {len(ev.get('sections', []))}")
        resources = [x for x in row["resources"] if x["kind"] != "asset"]
        seen: set[str] = set()
        lines.append("")
        lines.append("SUPERFICIE DE ATAQUE OBSERVADA:")
        status_counts: dict[str, int] = {}
        for item in resources:
            key = str(item["status"]) if item["status"] is not None else "?"
            status_counts[key] = status_counts.get(key, 0) + 1
        if status_counts:
            lines.append("  Resumen HTTP: " + " · ".join(
                f"{status}={count}" for status, count in sorted(status_counts.items())
            ))
        for item in row["surface"]:
            key = f"{item.get('type')}:{item.get('value')}"
            if key in seen:
                continue
            seen.add(key)
            lines.append(f"  [{str(item.get('type')).upper()}] {item.get('value')}")
            lines.append(f"    Relevancia: {item.get('why')}")
        for item in sorted(resources, key=lambda x: (0 if x["kind"] == "interesting" else 1, x["url"])):
            if item["url"] in seen:
                continue
            seen.add(item["url"])
            label = labels.get(item["kind"], item["kind"].upper())
            lines.append(f"  [{label}] HTTP {item['status'] if item['status'] is not None else '?'}  {item['url']}")
            status = item["status"]
            if "?" in item["url"]:
                reason = "Acepta parámetros observados; se correlaciona con hipótesis de validación de entrada cuando aplica."
            elif status == 500:
                reason = "El endpoint produjo una condición excepcional del servidor; la respuesta se analiza aparte para determinar si expone evidencia de seguridad."
            elif status == 401:
                reason = "Frontera de autenticación observada: el recurso exige identidad/autorización."
            elif status == 403:
                reason = "Control de acceso/restricción observado; no implica por sí solo bypass ni vulnerabilidad."
            elif item["kind"] == "interesting":
                reason = "Endpoint de API/autenticación/administración/operación observado; se prioriza por su función, no porque sea vulnerable."
            else:
                reason = why.get(item["kind"], why["resource"])
            lines.append(f"    Por qué aparece: {reason}")
            if item["source"]:
                lines.append(f"    Descubierto desde: {item['source']}")
        suppressed = len([x for x in row["resources"] if x["kind"] == "asset"])
        if suppressed:
            lines.append(f"  Ruido omitido: {suppressed} assets estáticos.")

        lines.append("")
        lines.append("COBERTURA REAL:")
        lines.append("  Evaluado: " + (", ".join(row["evaluated"]) or "nada"))
        lines.append("  Pendiente conocido: " + (", ".join(row["unevaluated"]) or "ninguno identificado por el modelo actual"))
        lines.append("  Nota: esto no demuestra cobertura exhaustiva; consulte el alcance exacto de cada comprobación.")
        lines.append(f"  Hallazgos de riesgo sustentados por evidencia: {len(row['findings'])}")
        if row["hypotheses"]:
            lines.append("")
            lines.append("HIPÓTESIS DE VALIDACIÓN:")
            for hypothesis in row["hypotheses"]:
                classes = ", ".join(str(x) for x in hypothesis.get("candidate_classes", []))
                subject = hypothesis.get("url") or hypothesis.get("endpoint") or row["target"]
                lines.append(f"  - {hypothesis.get('hypothesis', 'hipótesis')}: {subject}")
                if hypothesis.get("confidence"):
                    lines.append("    Confianza de identidad: " + str(hypothesis["confidence"]))
                if classes:
                    lines.append("    Clases candidatas: " + classes)
                if hypothesis.get("reason"):
                    lines.append("    Por qué: " + str(hypothesis["reason"]))
                recipe = hypothesis.get("validation_recipe")
                if isinstance(recipe, dict):
                    method = recipe.get("method")
                    inputs = ", ".join(str(x) for x in recipe.get("inputs", []))
                    if method or inputs:
                        lines.append("    Entrada: " + " · ".join(x for x in (
                            f"método={method}" if method else "",
                            f"inputs={inputs}" if inputs else "",
                        ) if x))
                    for check in recipe.get("checks", []):
                        if isinstance(check, dict):
                            lines.append(f"    Probar {check.get('class')}: {check.get('objective')}")
                    if recipe.get("success_rule"):
                        lines.append("    Regla de promoción: " + str(recipe["success_rule"]))
                    if recipe.get("preserve"):
                        lines.append("    Evidencia a preservar: " + ", ".join(str(x) for x in recipe["preserve"]))
        if row["findings"]:
            evidence_by_id = {item.id: item for item in assessment.evidence}
            lines.append("")
            lines.append("HALLAZGOS:")
            for finding in row["findings"]:
                lines.append(f"  - [{finding.status.value.upper()}] {finding.description}")
                lines.append(f"    Evidencias correlacionadas: {len(finding.evidence_ids)}")
                evidence_rows = [
                    evidence_by_id[evidence_id].content
                    for evidence_id in finding.evidence_ids
                    if evidence_id in evidence_by_id
                    and isinstance(evidence_by_id[evidence_id].content, dict)
                ]
                if evidence_rows:
                    representative = evidence_rows[0]
                    severity = representative.get("severity")
                    matched = representative.get("matched_at")
                    template = representative.get("template_id")
                    classification = representative.get("classification")
                    cwe = representative.get("cwe")
                    confidence = representative.get("confidence")
                    details = [x for x in (
                        f"severidad={severity}" if severity else None,
                        f"evidencia={matched}" if matched else None,
                        f"prueba={template}" if template else None,
                        f"clasificación={classification}" if classification else None,
                        str(cwe) if cwe else None,
                        f"confianza={confidence}" if confidence else None,
                    ) if x]
                    if details:
                        lines.append("    " + " · ".join(details))
                    if representative.get("impact_demonstrated"):
                        lines.append("    Impacto demostrado: " + str(representative["impact_demonstrated"]))
                    validation = representative.get("validation")
                    if isinstance(validation, dict):
                        lines.append("    Cómo validar: " + str(validation.get("goal", "")))
                        command = validation.get("safe_reproduction")
                        if command:
                            lines.append("    Reproducción segura: " + " ".join(str(x) for x in command))
                    urls = list(dict.fromkeys(
                        str(row.get("url") or row.get("matched_at"))
                        for row in evidence_rows
                        if row.get("url") or row.get("matched_at")
                    ))
                    if urls:
                        lines.append("    Evidencia observada en: " + ", ".join(urls[:3]))
                        if len(urls) > 3:
                            lines.append(f"    … {len(urls) - 3} endpoint(s) adicional(es) correlacionado(s).")
        else:
            lines.append("  0 hallazgos no significa que el objetivo sea seguro.")
        if row["tools"]:
            lines.append("  Capacidades/herramientas ejecutadas: " + ", ".join(row["tools"]))
        if row["executions"]:
            lines.append("")
            lines.append("TRAZA DE EJECUCIÓN:")
            for execution in row["executions"]:
                command = " ".join(str(x) for x in execution.get("command", []))
                lines.append(f"  - {execution.get('tool')}: {execution.get('purpose')}")
                if command:
                    lines.append(f"    Comando: {command}")
        budget_decisions = [x for x in row["decisions"] if x.get("requests") is not None]
        if budget_decisions:
            last = budget_decisions[-1]
            if last.get("budget") is None:
                lines.append(f"  Recon web: frontier de evidencia agotado tras {last.get('requests')} solicitudes; candidatos restantes: {last.get('remaining_candidates')}.")
            else:
                lines.append(f"  Recon web: límite explícito de QA alcanzado/considerado ({last.get('budget')}); solicitudes: {last.get('requests')}; candidatos restantes: {last.get('remaining_candidates')}.")
        if row["next"]:
            lines.append("")
            lines.append("SIGUIENTES FASES:")
            for step in row["next"]:
                tools = ", ".join(step["tools"]) or "sin adapter verificado en catálogo"
                lines.append(f"  - {step['capability']}: falta {', '.join(step['missing'])}.")
                lines.append(f"    Por qué: {step['reason']}")
                lines.append(f"    Adapters verificados candidatos: {tools}.")
                providers = step.get("providers", [])
                if providers:
                    names = ", ".join(sorted({str(item.get("name")) for item in providers}))
                    lines.append(f"    Providers locales pertinentes detectados: {names}.")
                    if not any(item.get("safe_adapter_available") for item in providers):
                        lines.append("    Estado: capacidad detectada, pero sin contrato de ejecución verificado; no se ejecutó por nombre.")
        lines.append("")
    return "\n".join(lines).rstrip()



def export_recon(path: Path, assessment: Any):
    from .reporting import write_exports
    return write_exports(path, assessment)


def write_surface_report_html(path: Path, assessment: Any) -> Path:
    from .reporting import write_human_report
    return write_human_report(path, assessment)
