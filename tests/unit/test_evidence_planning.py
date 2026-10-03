from surface_recon.tooling import evidence_required_subcapabilities


def _hypothesis(name):
    return {"evidence": {"kind": "security-hypothesis", "hypothesis": name}}


def test_input_evidence_adds_only_relevant_validation_classes():
    required = evidence_required_subcapabilities([_hypothesis("input-validation")])
    assert required == ("client-side-injection-testing", "injection-testing")


def test_authorization_evidence_adds_access_control_validation():
    required = evidence_required_subcapabilities([_hypothesis("authorization-boundary")])
    assert required == ("access-control-testing",)


def test_unrelated_observations_do_not_create_security_validation_requirements():
    observations = [{"evidence": {"kind": "technology", "signals": ["Astro"]}}]
    assert evidence_required_subcapabilities(observations) == ()


def test_assessment_promotes_observed_input_hypothesis_into_coverage_need(monkeypatch):
    from surface_recon.assessment import assess_targets
    from surface_recon.core import CoreExecution

    core = CoreExecution(True, [{
        "description": "input surface",
        "finding": False,
        "source": "surface-recon-core",
        "evidence": {"kind": "security-hypothesis", "hypothesis": "input-validation"},
    }], ("http-probing", "technology-fingerprinting", "error-handling-analysis",
         "input-surface-analysis"), [])
    monkeypatch.setattr("surface_recon.core.recon_target", lambda target: core)
    monkeypatch.setattr("surface_recon.tooling.discover_tools", lambda capability_id: [])
    monkeypatch.setattr("surface_recon.tooling.providers_for", lambda required: [])

    assessment = assess_targets(["https://example.test"])
    required = assessment.capabilities[0].required_subcapabilities

    assert "injection-testing" in required
    assert "client-side-injection-testing" in required
    assert "access-control-testing" not in required
    assert "injection-testing" in assessment.coverage[0].unevaluated
    decisions = [
        evidence.content for evidence in assessment.evidence
        if isinstance(evidence.content, dict)
        and evidence.content.get("reason") == "evidence-derived-validation-plan"
    ]
    assert decisions
    assert set(decisions[0]["required_subcapabilities"]) == {
        "injection-testing", "client-side-injection-testing"
    }


def test_surface_data_exposes_detected_provider_for_active_gap(monkeypatch):
    from surface_recon.assessment import assess_targets
    from surface_recon.core import CoreExecution
    from surface_recon.results import _surface_data
    from surface_recon.tooling import EnvironmentProvider

    core = CoreExecution(True, [{
        "description": "query input",
        "finding": False,
        "source": "surface-recon-core",
        "evidence": {"kind": "security-hypothesis", "hypothesis": "input-validation"},
    }], ("http-probing", "technology-fingerprinting", "template-detection",
         "content-discovery", "error-handling-analysis", "input-surface-analysis"), [])
    monkeypatch.setattr("surface_recon.core.recon_target", lambda target: core)
    monkeypatch.setattr("surface_recon.tooling.discover_tools", lambda capability_id: [])
    provider = EnvironmentProvider("/usr/bin/mysteryinject", "mysteryinject",
        ("package:mysteryinject",), ("injection-testing",), False)
    monkeypatch.setattr("surface_recon.tooling.providers_for", lambda required: [provider])

    row = _surface_data(assess_targets(["https://example.test"]))[0]

    injection = next(x for x in row["next"] if "injection-testing" in x["missing"])
    assert injection["providers"][0]["name"] == "mysteryinject"
    assert injection["providers"][0]["safe_adapter_available"] is False


def test_assessment_preserves_observed_technology_as_provider_hint(monkeypatch):
    from surface_recon.assessment import assess_targets
    from surface_recon.core import CoreExecution

    core = CoreExecution(True, [{
        "description": "technology",
        "finding": False,
        "source": "surface-recon-core",
        "evidence": {"kind": "technology", "signals": ["Server: nginx/1.26.0"]},
    }], ("http-probing", "technology-fingerprinting"), [])
    monkeypatch.setattr("surface_recon.core.recon_target", lambda target: core)
    monkeypatch.setattr("surface_recon.tooling.discover_tools", lambda capability_id: [])
    monkeypatch.setattr("surface_recon.tooling.providers_for", lambda required: [])

    assessment = assess_targets(["https://example.test"], use_extensions=False)

    assert assessment.targets[0].technology_hints == ["Server: nginx/1.26.0"]


def test_service_handoff_is_actionable_without_claiming_vulnerability():
    from surface_recon.assessment import _service_validation_observation

    observation = _service_validation_observation("192.0.2.10", {
        "port": 3306, "service": "mysql", "product": "MariaDB",
        "version": "12.3", "method": "probed",
    })

    evidence = observation["evidence"]
    assert evidence["kind"] == "security-hypothesis"
    assert evidence["hypothesis"] == "database-service"
    assert evidence["endpoint"] == "192.0.2.10:3306"
    assert evidence["confidence"] == "fingerprinted"
    assert observation["finding"] is False
    objectives = [row["objective"] for row in evidence["validation_recipe"]["checks"]]
    assert any("frontera de autenticación" in objective for objective in objectives)
    assert all("adivinación de credenciales" not in objective.lower() for objective in objectives)


def test_rpc_handoff_avoids_mutating_validation():
    from surface_recon.assessment import _service_validation_observation

    observation = _service_validation_observation("192.0.2.10", {
        "port": 135, "service": "msrpc", "product": "Microsoft Windows RPC",
        "method": "probed",
    })

    evidence = observation["evidence"]
    assert evidence["hypothesis"] == "rpc-interface"
    objectives = [row["objective"] for row in evidence["validation_recipe"]["checks"]]
    assert any("interfaces RPC" in objective for objective in objectives)
    assert any("sin invocar operaciones mutantes" in objective for objective in objectives)
