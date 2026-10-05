"""Assessment status aggregation."""

from collections.abc import Iterable

from .model import AssessmentStatus, AvailabilityState, Capability, Coverage, Limitation


def _url_host(value: str) -> str:
    """Format a host literal for URL authority without changing its scope identity."""
    return f"[{value}]" if ":" in value and not value.startswith("[") else value


def _service_validation_observation(address: str, service: dict) -> dict | None:
    name = str(service.get("service") or "").lower()
    families = {
        "remote-access": {"ssh"},
        "file-sharing": {"smb", "microsoft-ds", "netbios-ssn"},
        "database-service": {"mysql", "postgresql", "ms-sql-s", "mongodb", "redis"},
        "rpc-interface": {"msrpc", "rpcbind", "sunrpc"},
        "realtime-interface": {"websocket", "ws"},
    }
    family = next((key for key, names in families.items() if name in names), None)
    if family is None:
        return None
    port = int(service.get("port") or 0)
    demonstrated = bool(
        service.get("product") or service.get("version") or service.get("method") == "probed"
    )
    checks = {
        "remote-access": [
            "confirmar protocolo/versión y configuración criptográfica soportada",
            "validar la política de autenticación sin adivinación de credenciales",
        ],
        "file-sharing": [
            "confirmar identidad/dialecto SMB y requisitos de firma",
            "validar frontera anónima/invitado y exposición de recursos compartidos autorizados",
        ],
        "database-service": [
            "confirmar protocolo/producto/versión antes de conclusiones específicas de versión",
            "validar exposición de red prevista, protección de transporte y frontera de autenticación",
        ],
        "rpc-interface": [
            "confirmar endpoint mapper e interfaces RPC realmente expuestas",
            "validar frontera de autenticación y exposición remota prevista sin invocar operaciones mutantes",
        ],
        "realtime-interface": [
            "confirmar endpoint de handshake WebSocket y frontera de autenticación/sesión",
            "validar control de Origin y comportamiento del handshake no autenticado",
        ],
    }[family]
    return {
        "description": f"Validation hypothesis for observed {name} service on {address}:{port}",
        "evidence": {
            "kind": "security-hypothesis", "hypothesis": family,
            "endpoint": f"{address}:{port}", "service": name,
            "confidence": "fingerprinted" if demonstrated else "provider-hint",
            "reason": (
                "el provider aportó evidencia de fingerprint"
                if demonstrated else
                "el provider aportó una pista de servicio; confirmar identidad antes de conclusiones específicas"
            ),
            "validation_recipe": {
                "checks": [{"class": family, "objective": item} for item in checks],
                "success_rule": "Promover solo una condición demostrada por evidencia preservada de protocolo/configuración.",
                "preserve": ["target", "puerto", "evidencia de protocolo", "respuesta/configuración observada"],
            },
        },
        "finding": False, "source": "surface-recon-planner",
    }


def aggregate_coverage(
    target_id: str,
    capabilities: list[Capability],
    limitations: list[Limitation],
) -> Coverage:
    """Summarize only demonstrated capability coverage."""
    considered = [
        subcapability
        for cap in capabilities
        for subcapability in (cap.required_subcapabilities or [cap.id])
    ]
    evaluated = [
        subcapability
        for cap in capabilities
        for subcapability in (
            cap.evaluated_subcapabilities
            if cap.required_subcapabilities
            else ([cap.id] if cap.availability is AvailabilityState.AVAILABLE and cap.status == "completed" else [])
        )
    ]
    # A demonstrated full capability supersedes its earlier partial marker.
    # Keep partial markers only when they are the strongest evidence available.
    evaluated_set = set(evaluated)
    evaluated = [
        item for item in evaluated
        if not (item.endswith("-partial") and item.removesuffix("-partial") in evaluated_set)
    ]
    unevaluated = [item for item in considered if item not in evaluated]
    return Coverage(target_id, considered, evaluated, unevaluated, list(limitations))


def aggregate_status(statuses: Iterable[AssessmentStatus]) -> AssessmentStatus:
    values = list(statuses)
    if not values:
        return AssessmentStatus.FAILED
    if all(value is AssessmentStatus.COMPLETED for value in values):
        return AssessmentStatus.COMPLETED
    if all(value is AssessmentStatus.FAILED for value in values):
        return AssessmentStatus.FAILED
    if any(value in {AssessmentStatus.PARTIAL, AssessmentStatus.FAILED} for value in values):
        return AssessmentStatus.PARTIAL
    if any(value is AssessmentStatus.RUNNING for value in values):
        return AssessmentStatus.RUNNING
    return AssessmentStatus.PENDING


def assess_targets(values: list[str], *, use_extensions: bool = True, progress=None) -> "Assessment":
    """Classify and assess authorized targets.

    Surface_Recon-owned reconnaissance runs first. Optional external extensions
    may enrich coverage but are never required for the owned URL core.
    """
    from .capabilities import applicable_capabilities
    from .classification import classify_target
    from .model import Assessment, Coverage, Limitation, ScopeState, Target

    targets = []
    coverage = []
    limitations = []
    all_findings = []
    all_observations = []
    all_evidence = []
    all_capabilities = []

    for index, value in enumerate(values, start=1):
        target = classify_target(
            Target(
                id=f"target-{index}",
                value=value,
                scope_state=ScopeState.AUTHORIZED,
            )
        )
        targets.append(target)

        # Submitted targets are the only assessment scope. Resources discovered
        # while observing a target remain context-only unless separately submitted.
        target.require_authorized()
        capabilities = applicable_capabilities(target)
        all_capabilities.extend(capabilities)

        if target.target_type is None:
            limitation = Limitation(
                target_id=target.id,
                reason="Target classification unresolved.",
                impact="No applicable reconnaissance capability could be selected.",
            )
            limitations.append(limitation)
            coverage.append(
                Coverage(
                    target_id=target.id,
                    unevaluated=["classification-dependent reconnaissance"],
                    limitations=[limitation],
                )
            )
            continue

        capability_limitations = []
        from .findings import findings_from_capability_result
        from .tooling import (
            evidence_required_subcapabilities,
            execute_tool,
            providers_for,
            select_tools_for_gaps,
        )

        for capability in capabilities:
            if capability.availability is AvailabilityState.AVAILABLE and capability.status is None:
                executions = []
                web_pivots_seen: set[str] = set()
                if capability.id == "http-recon" and target.target_type == "url":
                    from .core import recon_target
                    core = recon_target(target, progress=progress) if progress is not None else recon_target(target)
                    if core.succeeded:
                        target.discovered_resources.extend(
                            item for item in core.discovered if item not in target.discovered_resources
                        )
                        target.extension_hints.extend(
                            str(obs["evidence"]["url"])
                            for obs in core.observations
                            if isinstance(obs.get("evidence"), dict)
                            and obs["evidence"].get("kind") == "interesting"
                            and obs["evidence"].get("url")
                            and str(obs["evidence"]["url"]) not in target.extension_hints
                        )
                        for obs in core.observations:
                            evidence = obs.get("evidence")
                            if not isinstance(evidence, dict) or evidence.get("kind") != "technology":
                                continue
                            for signal in evidence.get("signals", []):
                                signal = str(signal)
                                if signal not in target.technology_hints:
                                    target.technology_hints.append(signal)
                        executions.append(type("CoreResult", (), {
                            "succeeded": True, "tool_id": "surface-recon-core",
                            "observations": core.observations,
                            "covered_subcapabilities": core.covered_subcapabilities,
                        })())
                elif target.target_type in {"path", "binary", "directory", "repository", "host", "network", "opaque"}:
                    from .universal_core import fingerprint_host_services, recon_artifact, recon_host, recon_network, recon_opaque, recon_path, static_source_review
                    if target.target_type in {"path", "binary"}:
                        observations_owned, covered_owned = recon_artifact(target)
                    elif target.target_type in {"directory", "repository"}:
                        observations_owned, covered_owned = recon_path(target)
                        if target.target_type == "repository":
                            static_observations, static_covered = static_source_review(target)
                            observations_owned.extend(static_observations)
                            covered_owned = tuple(dict.fromkeys((*covered_owned, *static_covered)))
                    elif target.target_type == "host":
                        observations_owned, covered_owned = recon_host(target)
                        # Evidence-driven pivot: a reachable HTTP-family port on the
                        # authorized host becomes web surface without expanding scope.
                        port_rows = [o for o in observations_owned
                                     if isinstance(o.get("evidence"), dict)
                                     and o["evidence"].get("kind") == "ports"]
                        for row in port_rows:
                            fingerprint_observations, fingerprint_covered = fingerprint_host_services(target, row)
                            observations_owned.extend(fingerprint_observations)
                            covered_owned = tuple(dict.fromkeys((*covered_owned, *fingerprint_covered)))
                            for service in row["evidence"].get("reachable", []):
                                port = int(service.get("port", 0))
                                if port not in {80, 443, 8080, 8443}:
                                    continue
                                scheme = "https" if port in {443, 8443} else "http"
                                pivot = Target(f"{target.id}-web-{port}",
                                               f"{scheme}://{_url_host(target.value)}:{port}",
                                               target.scope_state, target_type="url")
                                if pivot.value in web_pivots_seen:
                                    continue
                                web_pivots_seen.add(pivot.value)
                                from .core import recon_target
                                web = recon_target(pivot)
                                if web.succeeded:
                                    observations_owned.extend(web.observations)
                                    covered_owned = tuple(dict.fromkeys(
                                        (*covered_owned, *web.covered_subcapabilities)
                                    ))
                                    target.discovered_resources.extend(
                                        item for item in web.discovered
                                        if item not in target.discovered_resources
                                    )
                                    observations_owned.append({
                                        "description": f"Pivoted from reachable TCP/{port} into web reconnaissance",
                                        "evidence": {"kind":"decision","reason":"service-to-web-pivot",
                                                     "port":port,"url":pivot.value},
                                        "finding": False,"source":"surface-recon-core",
                                    })
                    elif target.target_type == "network":
                        observations_owned, covered_owned = recon_network(target)
                        host_rows = [o for o in observations_owned
                                     if isinstance(o.get("evidence"), dict)
                                     and o["evidence"].get("kind") == "network-hosts"]
                        for row in host_rows:
                            for item in row["evidence"].get("hosts", []):
                                derived = Target(f"{target.id}-host-{item['address']}",
                                                 item["address"], target.scope_state, target_type="host")
                                host_observations, host_covered = recon_host(derived)
                                observations_owned.extend(host_observations)
                                covered_owned = tuple(dict.fromkeys((*covered_owned, *host_covered)))
                                for port_row in [o for o in host_observations
                                                 if isinstance(o.get("evidence"), dict)
                                                 and o["evidence"].get("kind") == "ports"]:
                                    fp_obs, fp_covered = fingerprint_host_services(derived, port_row)
                                    observations_owned.extend(fp_obs)
                                    covered_owned = tuple(dict.fromkeys((*covered_owned, *fp_covered)))
                                    for service in port_row["evidence"].get("reachable", []):
                                        port = int(service.get("port", 0))
                                        if port not in {80, 443, 8080, 8443}:
                                            continue
                                        scheme = "https" if port in {443, 8443} else "http"
                                        pivot = Target(f"{derived.id}-web-{port}",
                                                       f"{scheme}://{_url_host(derived.value)}:{port}",
                                                       target.scope_state, target_type="url")
                                        if pivot.value in web_pivots_seen:
                                            continue
                                        web_pivots_seen.add(pivot.value)
                                        from .core import recon_target
                                        web = recon_target(pivot)
                                        if web.succeeded:
                                            observations_owned.extend(web.observations)
                                            covered_owned = tuple(dict.fromkeys(
                                                (*covered_owned, *web.covered_subcapabilities)
                                            ))
                                            target.discovered_resources.extend(
                                                x for x in web.discovered
                                                if x not in target.discovered_resources
                                            )
                                            observations_owned.append({
                                                "description": f"Pivoted network host {derived.value} TCP/{port} into web reconnaissance",
                                                "evidence": {"kind":"decision","reason":"network-host-to-web-pivot",
                                                             "host":derived.value,"port":port,"url":pivot.value},
                                                "finding": False,"source":"surface-recon-core",
                                            })
                    else:
                        observations_owned, covered_owned = recon_opaque(target)
                    if observations_owned:
                        executions.append(type("CoreResult", (), {
                            "succeeded": True, "tool_id": "surface-recon-core",
                            "observations": observations_owned,
                            "covered_subcapabilities": covered_owned,
                        })())
                # Evidence can make deeper validation pertinent after the owned
                # reconnaissance phase. Do not require these classes globally.
                core_observations = [
                    obs for item in executions if item.succeeded
                    for obs in item.observations
                ]
                evidence_requirements = evidence_required_subcapabilities(core_observations)
                added_requirements = []
                planner_observations = []
                for required in evidence_requirements:
                    if required not in capability.required_subcapabilities:
                        capability.required_subcapabilities.append(required)
                        added_requirements.append(required)
                if added_requirements:
                    planner_observations.append({
                        "description": "Planner added deeper validation needs from observed security hypotheses",
                        "evidence": {
                            "kind": "decision",
                            "reason": "evidence-derived-validation-plan",
                            "required_subcapabilities": added_requirements,
                        },
                        "finding": False,
                        "source": "surface-recon-planner",
                    })

                if use_extensions:
                    covered_by_core = {
                        subcapability
                        for item in executions if item.succeeded
                        for subcapability in item.covered_subcapabilities
                    }
                    missing_after_core = set(capability.required_subcapabilities) - covered_by_core
                    selected_tools = select_tools_for_gaps(capability.id, missing_after_core)
                    if selected_tools:
                        provider_results = [execute_tool(tool, target) for tool in selected_tools]
                        executions.extend(provider_results)
                        for provider_result in provider_results:
                            if not provider_result.succeeded:
                                planner_observations.append({
                                    "description": f"Provider {provider_result.tool_id} did not add coverage",
                                    "evidence": {
                                        "kind": "decision",
                                        "reason": "provider-coverage-not-demonstrated",
                                        "tool": provider_result.tool_id,
                                        "detail": provider_result.error,
                                    },
                                    "finding": False,
                                    "source": "surface-recon-planner",
                                })
                        if target.target_type in {"host", "network"}:
                            for provider_result in provider_results:
                                if not provider_result.succeeded:
                                    continue
                                for provider_observation in provider_result.observations:
                                    evidence = provider_observation.get("evidence", {})
                                    if evidence.get("kind") != "nmap-surface":
                                        continue
                                    for host in evidence.get("hosts", []):
                                        address = (host.get("addresses") or [target.value])[0]
                                        for service in host.get("services", []):
                                            port = int(service.get("port", 0))
                                            name = str(service.get("service") or "").lower()
                                            validation = _service_validation_observation(address, service)
                                            if validation is not None:
                                                planner_observations.append(validation)
                                            if not (
                                                name.startswith("http") or name.startswith("ssl/http")
                                            ):
                                                continue
                                            tunnel = str(service.get("tunnel") or "").lower()
                                            scheme = "https" if (
                                                tunnel == "ssl" or "https" in name
                                                or name.startswith("ssl/") or port in {443, 8443}
                                            ) else "http"
                                            pivot = Target(
                                                f"{target.id}-provider-web-{address}-{port}",
                                                f"{scheme}://{_url_host(address)}:{port}",
                                                target.scope_state, target_type="url",
                                            )
                                            if pivot.value in web_pivots_seen:
                                                continue
                                            web_pivots_seen.add(pivot.value)
                                            from .core import recon_target
                                            web = recon_target(pivot)
                                            if web.succeeded:
                                                observations_owned = list(web.observations)
                                                observations_owned.append({
                                                    "description": f"Pivoted provider-observed {address} TCP/{port} into web reconnaissance",
                                                    "evidence": {
                                                        "kind": "decision",
                                                        "reason": "provider-service-to-web-pivot",
                                                        "host": address, "port": port, "url": pivot.value,
                                                    },
                                                    "finding": False, "source": "surface-recon-planner",
                                                })
                                                from .tooling import ToolExecution
                                                executions.append(ToolExecution(
                                                    "surface-recon-core", True,
                                                    observations_owned,
                                                    covered_subcapabilities=web.covered_subcapabilities,
                                                ))
                                                target.discovered_resources.extend(
                                                    item for item in web.discovered
                                                    if item not in target.discovered_resources
                                                )

                successful = [item for item in executions if item.succeeded]
                observations = [obs for item in successful for obs in item.observations]
                observations.extend(planner_observations)
                if use_extensions:
                    evaluated_now = {
                        subcapability
                        for item in successful
                        for subcapability in item.covered_subcapabilities
                    }
                    remaining_now = set(capability.required_subcapabilities) - evaluated_now
                    environment = providers_for(remaining_now)
                    if environment:
                        observations.append({
                            "description": f"Environment capability inventory selected {len(environment)} relevant provider(s)",
                            "evidence": {
                                "kind": "environment-providers",
                                "providers": [
                                    {"name": row.name, "executable": row.executable,
                                     "subcapabilities": list(row.inferred_subcapabilities),
                                     "safe_adapter_available": row.executable_adapter_available}
                                    for row in environment
                                ],
                            },
                            "finding": False, "source": "surface-recon-provider-discovery",
                        })
                if successful:
                    capability.tools_used = [item.tool_id for item in successful]
                    capability.evaluated_subcapabilities = sorted({
                        subcapability
                        for item in successful
                        for subcapability in item.covered_subcapabilities
                    })
                    missing = set(capability.required_subcapabilities) - set(capability.evaluated_subcapabilities)
                    capability.status = "partial" if missing else "completed"
                    findings, normalized_observations, normalized_evidence = findings_from_capability_result(
                        target_id=target.id,
                        capability_id=capability.id,
                        observations=observations,
                    )
                    all_findings.extend(findings)
                    all_observations.extend(normalized_observations)
                    all_evidence.extend(normalized_evidence)
                else:
                    capability.status = "failed"

        for capability in capabilities:
            if capability.availability is not AvailabilityState.AVAILABLE:
                capability_limitations.append(
                    Limitation(
                        target_id=target.id,
                        capability_id=capability.id,
                        reason=f"Capability is {capability.availability.value}.",
                        impact="Applicable evaluation was not completed; absence of risk cannot be inferred.",
                    )
                )
            elif capability.status == "partial":
                missing = sorted(set(capability.required_subcapabilities) - set(capability.evaluated_subcapabilities))
                capability_limitations.append(
                    Limitation(
                        target_id=target.id,
                        capability_id=capability.id,
                        reason=f"Subcapabilities not evaluated: {', '.join(missing)}.",
                        impact="Coverage is partial; completed tooling does not imply complete capability coverage.",
                    )
                )
            elif capability.status == "failed":
                capability_limitations.append(
                    Limitation(
                        target_id=target.id,
                        capability_id=capability.id,
                        reason="Capability execution failed.",
                        impact="Coverage is partial; failure is not successful evaluation.",
                    )
                )

        limitations.extend(capability_limitations)
        coverage.append(aggregate_coverage(target.id, capabilities, capability_limitations))

    incomplete_coverage = any(item.unevaluated for item in coverage)
    status = (
        AssessmentStatus.PARTIAL
        if limitations or incomplete_coverage
        else AssessmentStatus.COMPLETED
    )

    return Assessment(
        id="assessment-local",
        targets=targets,
        status=status,
        capabilities=all_capabilities,
        coverage=coverage,
        limitations=limitations,
        findings=all_findings,
        observations=all_observations,
        evidence=all_evidence,
    )
