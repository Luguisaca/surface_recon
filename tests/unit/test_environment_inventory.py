from surface_recon.tooling import infer_subcapabilities, inventory_environment_providers


def test_semantic_capability_inference_is_not_tool_name_catalog():
    caps = infer_subcapabilities("network exploration and security auditing tool")
    assert caps == ("host-discovery", "port-discovery", "service-fingerprinting")


def test_environment_inventory_uses_external_metadata_without_executing_tool(tmp_path, monkeypatch):
    tool = tmp_path / "mysteryscan"
    tool.write_text("do not execute", encoding="utf-8")
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr("surface_recon.tooling.platform.system", lambda: "Linux")
    rows = inventory_environment_providers({"mysteryscan": "HTTP probe and web fingerprint utility"})
    assert len(rows) == 1
    assert rows[0].name == "mysteryscan"
    assert rows[0].executable_adapter_available is False
    assert set(rows[0].inferred_subcapabilities) == {"http-probing", "technology-fingerprinting"}


def test_environment_inventory_does_not_claim_unknown_capabilities(tmp_path, monkeypatch):
    (tmp_path / "opaque-tool").write_text("x", encoding="utf-8")
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr("surface_recon.tooling.platform.system", lambda: "Linux")
    assert inventory_environment_providers() == []


def test_semantic_inventory_can_describe_deeper_validation_without_executable_adapter(tmp_path, monkeypatch):
    tool = tmp_path / "mysteryinject"
    tool.write_text("do not execute", encoding="utf-8")
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr("surface_recon.tooling.platform.system", lambda: "Linux")

    rows = inventory_environment_providers({
        "mysteryinject": "SQL injection scanner and database takeover tool"
    })

    assert len(rows) == 1
    assert "injection-testing" in rows[0].inferred_subcapabilities
    assert rows[0].executable_adapter_available is False


def test_web_fuzzer_metadata_does_not_overclaim_injection_testing():
    caps = infer_subcapabilities("fast web fuzzer for content discovery")
    assert "content-discovery" in caps
    assert "injection-testing" not in caps


def test_static_analysis_is_inferred_from_capability_description_not_tool_name():
    caps = infer_subcapabilities("language-agnostic static analysis for source code")
    assert "static-analysis" in caps
